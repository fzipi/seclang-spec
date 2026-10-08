import SecLang.Syntax
import SecLang.Transformations
/-! The variable store of one transaction, populated from the request and response per
`spec/05-variables.md` and `spec/09-body-processors.md` (URL-encoded bodies only). -/
namespace SecLang

structure Member where
  key : String
  value : ByteArray

/-- Canonical collection name → members; a scalar is one member with the empty key. -/
abbrev Store := List (String × List Member)

def Store.get (st : Store) (coll : String) : List Member := (st.lookup coll).getD []
def Store.set (st : Store) (coll : String) (ms : List Member) : Store := (coll, ms) :: st.filter (·.1 != coll)

def text (s : String) : ByteArray := s.toUTF8
/-- A configuration string in the store's key convention (Latin-1 form of its bytes). -/
def latin (s : String) : String := ofBytes s.toUTF8
def scalar (v : ByteArray) : List Member := [⟨"", v⟩]

structure Request where
  method : String := "GET"
  uri : String := "/"
  version : String := "HTTP/1.1"
  headers : List (String × String) := []
  body : Option String := none
  remoteAddr : String := "127.0.0.1"

structure Response where
  status : Nat := 200
  headers : List (String × String) := []
  body : String := ""

/-- Configuration-level settings the store depends on (`04`). The response MIME set has no
specified default (`04#secresponsebodymimetype`): none until set. -/
structure Settings where
  argSep : Char := '&'
  argsLimit : Option Nat := none
  requestBodyAccess : Bool := false
  responseBodyAccess : Bool := false
  mimeTypes : List String := []

def headerValue (hs : List (String × String)) (name : String) : Option String :=
  (hs.find? fun (k, _) => k.toLower == name.toLower).map (·.2)

def limitArgs (lim : Option Nat) (ms : List Member) : List Member :=
  match lim with | some n => ms.take n | none => ms

/-- `name=value` pairs split on `sep`, both sides URL-decoded (`05#args`, `09#urlencoded`: an
empty pair is ignored), capped by `SecArgumentsLimit`. -/
def parseArgs (sep : Char) (lim : Option Nat) (s : String) : List Member :=
  if s.isEmpty then [] else
  limitArgs lim <| ((s.splitOn (String.singleton sep)).filter (!·.isEmpty)).map fun pair =>
    let (n, v) := match pair.splitOn "=" with
      | [n] => (n, "") | n :: rest => (n, "=".intercalate rest) | [] => ("", "")
    ⟨ofBytes (urlDecode (text n)), urlDecode (text v)⟩

def namesOf (ms : List Member) : List Member := ms.map fun m => ⟨m.key, bytesOf m.key⟩
def combinedSize (ms : List Member) : Nat := ms.foldl (fun n m => n + (bytesOf m.key).size + m.value.size) 0
def natText (n : Nat) : List Member := scalar (text (toString n))

/-- Phase 1 store (`05`): request line, headers, cookies, query arguments. -/
def phase1Store (st : Settings) (r : Request) : Store :=
  let (path, query) := match r.uri.splitOn "?" with
    | [p] => (p, "") | p :: rest => (p, "?".intercalate rest) | [] => ("", "")
  let base := (path.splitOn "/").getLast?.getD path
  let getArgs := parseArgs st.argSep st.argsLimit query
  let headers := r.headers.map fun (k, v) => Member.mk (latin k) (text (trimBlanks v))
  let cookies := (r.headers.filter fun (k, _) => k.toLower == "cookie").flatMap fun (_, v) =>
    (v.splitOn ";").filterMap fun c =>
      let c := trimBlanks c
      if c.isEmpty then none else some (match c.splitOn "=" with
        | [n] => Member.mk (latin (trimBlanks n)) (text "")
        | n :: rest => Member.mk (latin (trimBlanks n)) (text (trimBlanks ("=".intercalate rest)))
        | [] => Member.mk "" (text ""))
  [("REQUEST_METHOD", scalar (text r.method)), ("REQUEST_URI", scalar (text r.uri)),
   ("REQUEST_URI_RAW", scalar (text r.uri)), ("REQUEST_FILENAME", scalar (text path)),
   ("REQUEST_BASENAME", scalar (text base)), ("QUERY_STRING", scalar (text query)),
   ("REQUEST_PROTOCOL", scalar (text r.version)),
   ("REQUEST_LINE", scalar (text s!"{r.method} {r.uri} {r.version}")),
   ("REMOTE_ADDR", scalar (text r.remoteAddr)), ("UNIQUE_ID", scalar (text "seclang-model")),
   ("REQUEST_HEADERS", headers), ("REQUEST_HEADERS_NAMES", namesOf headers),
   ("REQUEST_COOKIES", cookies), ("REQUEST_COOKIES_NAMES", namesOf cookies),
   ("ARGS_GET", getArgs), ("ARGS_GET_NAMES", namesOf getArgs), ("ARGS", getArgs),
   ("ARGS_NAMES", namesOf getArgs), ("ARGS_COMBINED_SIZE", natText (combinedSize getArgs)),
   ("REQUEST_BODY_LENGTH", natText 0), ("REQBODY_PROCESSOR", scalar (text ""))]

/-- Body processor from the `Content-Type` prefix (`09#processor-selection`) unless a
phase 1 `ctl:requestBodyProcessor` chose one. -/
def selectProcessor (override : Option String) (contentType : Option String) : String :=
  match override with
  | some p => p.toUpper
  | none => match contentType with
    | some ct =>
      if ct.toLower.startsWith "application/x-www-form-urlencoded" then "URLENCODED"
      else if ct.toLower.startsWith "multipart/form-data" then "MULTIPART" else ""
    | none => ""

structure Part where
  name : String
  filename : Option String
  headers : String
  content : ByteArray

/-- A `key=value` parameter of a `;`-separated header value, quotes removed. -/
def headerParam (v : String) (key : String) : Option String :=
  ((v.splitOn ";").map trimBlanks).findSome? fun p =>
    match p.splitOn "=" with
    | k :: rest@(_ :: _) =>
      if (trimBlanks k).toLower == key.toLower then
        let val := "=".intercalate rest
        some (if val.length ≥ 2 && val.startsWith "\"" && val.endsWith "\"" then String.ofList ((val.toList.drop 1).dropLast) else val)
      else none
    | _ => none

/-- One part: the header block up to the blank line, then the content. -/
def parsePart (piece : String) : Part :=
  let (hdrs, content) := match piece.splitOn "\r\n\r\n" with
    | [h] => (h, "")
    | h :: rest => (h, "\r\n\r\n".intercalate rest)
    | [] => ("", "")
  let disposition := ((hdrs.splitOn "\r\n").find? fun l => l.toLower.startsWith "content-disposition:").map fun l =>
    dropFirst (String.ofList (l.toList.dropWhile (· != ':')))
  { name := (disposition.bind (headerParam · "name")).getD "", filename := disposition.bind (headerParam · "filename"),
    headers := hdrs, content := text content }

/-- RFC 7578 (`09#multipart`): the parts and whether an anomaly was seen (data before the
first boundary, a bare LF line ending, or no closing delimiter). -/
def parseMultipart (boundary : String) (body : String) : List Part × Bool :=
  let delim := "--" ++ boundary
  let bareLF := (body.toList.zip ('\r' :: body.toList)).any fun (c, prev) => c == '\n' && prev != '\r'
  if !body.startsWith delim then ([], true) else
  let pieces := (String.ofList (body.toList.drop delim.length)).splitOn ("\r\n" ++ delim)
  match pieces.getLast? with
  | none => ([], true)
  | some last =>
    let closed := last.startsWith "--"
    let parts := (pieces.dropLast.filter fun p => p.startsWith "\r\n").map fun p => parsePart (String.ofList (p.toList.drop 2))
    (parts, bareLF || !closed)

/-- Phase 2 additions when the body is read (`09#urlencoded`, `05#request_body`, ADR-0022):
`access` and `processor` come from the settings as overridden by phase 1 `ctl`s. -/
def phase2Store (st : Settings) (r : Request) (access : Bool) (processor : Option String) (force : Bool) (store : Store) : Store :=
  match r.body with
  | none => store
  | some body =>
    if !access then store else
    let ct := headerValue r.headers "Content-Type"
    let proc := selectProcessor processor ct
    let get := store.get "ARGS_GET"
    -- multipart (`09#multipart`): fields become arguments, files become FILES*
    let (parts, bad) := if proc != "MULTIPART" then ([], false) else
      match ct.bind (headerParam · "boundary") with | some b => parseMultipart b body | none => ([], true)
    let fileParts := parts.filter (·.filename.isSome)
    let post := if proc == "URLENCODED" then parseArgs st.argSep none body
                else (parts.filter (·.filename.isNone)).map fun p => Member.mk (latin p.name) p.content
    let all := limitArgs st.argsLimit (get ++ post)
    let post := all.drop get.length
    let reqBody := if proc == "URLENCODED" || force then scalar (text body) else []
    let files := fileParts.filterMap fun p => p.filename.map fun f => Member.mk (latin p.name) (text f)
    let store := store |>.set "ARGS_POST" post |>.set "ARGS_POST_NAMES" (namesOf post)
      |>.set "ARGS" all |>.set "ARGS_NAMES" (namesOf all)
      |>.set "ARGS_COMBINED_SIZE" (natText (combinedSize all))
      |>.set "REQUEST_BODY" reqBody |>.set "REQUEST_BODY_LENGTH" (natText (text body).size)
      |>.set "REQBODY_PROCESSOR" (scalar (text proc))
    if proc != "MULTIPART" then store else
    store |>.set "FILES" files |>.set "FILES_NAMES" (namesOf files)
      |>.set "FILES_COMBINED_SIZE" (natText (fileParts.foldl (fun n p => n + p.content.size) 0))
      |>.set "MULTIPART_PART_HEADERS" (parts.map fun p => Member.mk (latin p.name) (text p.headers))
      |>.set "MULTIPART_STRICT_ERROR" (natText (if bad then 1 else 0))

/-- Phase 3 additions (`05#response_status`, `05#response_headers`). -/
def phase3Store (resp : Option Response) (store : Store) : Store :=
  match resp with
  | none => store
  | some rs =>
    let hs := rs.headers.map fun (k, v) => Member.mk (latin k) (text (trimBlanks v))
    store |>.set "RESPONSE_STATUS" (natText rs.status) |>.set "RESPONSE_HEADERS" hs

/-- Phase 4 additions (`05#response_body`, `04#secresponsebodyaccess`): the body when access
is on and the MIME type (parameters stripped) is listed. -/
def phase4Store (st : Settings) (resp : Option Response) (store : Store) : Store :=
  match resp with
  | none => store
  | some rs =>
    let ct := (headerValue rs.headers "Content-Type").map fun c => trimBlanks ((c.splitOn ";").headD "")
    if st.responseBodyAccess && ct.any st.mimeTypes.contains then store.set "RESPONSE_BODY" (scalar (text rs.body)) else store

#guard (parseArgs '&' none "a=1&a=2&b=3").map (fun m => (m.key, ofBytes m.value)) == [("a", "1"), ("a", "2"), ("b", "3")]
#guard (parseArgs '&' none "a=1&b&c=x+y%20z&d=%zz").map (fun m => (m.key, ofBytes m.value)) == [("a", "1"), ("b", ""), ("c", "x y z"), ("d", "%zz")]
#guard (parseArgs ';' none "a=1;b=2").map (·.key) == ["a", "b"]
#guard (parseArgs '&' (some 2) "a=1&b=2&c=3").map (·.key) == ["a", "b"]
#guard ((phase1Store {} { uri := "/dir/file.php?x=1" }).get "REQUEST_FILENAME").map (ofBytes ·.value) == ["/dir/file.php"]
#guard ((phase1Store {} { uri := "/dir/file.php?x=1" }).get "REQUEST_BASENAME").map (ofBytes ·.value) == ["file.php"]
#guard ((phase1Store {} { uri := "/dir/file.php?x=1" }).get "QUERY_STRING").map (ofBytes ·.value) == ["x=1"]
#guard ((phase1Store {} { uri := "/", headers := [("Cookie", "a=1; b=2; a=3")] }).get "REQUEST_COOKIES").map (fun m => (m.key, ofBytes m.value)) == [("a", "1"), ("b", "2"), ("a", "3")]
#guard ((phase1Store {} { uri := "/", headers := [("X-Test", " Hello ")] }).get "REQUEST_HEADERS_NAMES").map (ofBytes ·.value) == ["X-Test"]
#guard (let s := phase1Store { argsLimit := some 2 } { uri := "/?a=1&b=2" }
        let s := phase2Store { argsLimit := some 2, requestBodyAccess := true } { method := "POST", uri := "/?a=1&b=2", headers := [("Content-Type", "application/x-www-form-urlencoded")], body := some "p=1" } true none false s
        (s.get "ARGS").length) == 2
#guard (let s := phase2Store { requestBodyAccess := true } { uri := "/", headers := [("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")], body := some "p=1&q=2" } true none false (phase1Store {} { uri := "/" })
        ((s.get "REQBODY_PROCESSOR").map (ofBytes ·.value), (s.get "ARGS_POST").length, (s.get "REQUEST_BODY").map (ofBytes ·.value), (s.get "REQUEST_BODY_LENGTH").map (ofBytes ·.value))) == (["URLENCODED"], 2, ["p=1&q=2"], ["7"])
#guard (let s := phase2Store {} { uri := "/", headers := [("Content-Type", "text/plain")], body := some "a=1" } true none true (phase1Store {} { uri := "/" })
        ((s.get "REQUEST_BODY").map (ofBytes ·.value), (s.get "ARGS_POST").length)) == (["a=1"], 0)
#guard (let s := phase2Store {} { uri := "/", headers := [("Content-Type", "text/plain")], body := some "a=1" } true none false (phase1Store {} { uri := "/" })
        (s.get "REQUEST_BODY").length) == 0
#guard ((phase4Store { responseBodyAccess := true, mimeTypes := ["text/plain"] } (some { headers := [("Content-Type", "text/plain; charset=utf-8")], body := "leak" }) []).get "RESPONSE_BODY").map (ofBytes ·.value) == ["leak"]
#guard ((phase4Store { responseBodyAccess := true, mimeTypes := ["text/plain"] } (some { headers := [("Content-Type", "application/json")], body := "leak" }) []).get "RESPONSE_BODY").length == 0

def mpBody : String := "--XX\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\nhello\r\n--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nabc\r\n--XX--\r\n"
#guard (parseArgs '&' none "a=1&&b=2").map (·.key) == ["a", "b"]
#guard ((parseMultipart "XX" mpBody).1.map fun p => (p.name, p.filename, ofBytes p.content)) == [("t", none, "hello"), ("f", some "a.txt", "abc")]
#guard (parseMultipart "XX" mpBody).2 == false
#guard (parseMultipart "XX" "--XX\nContent-Disposition: form-data; name=\"t\"\n\nhello\n--XX--\n").2 == true
#guard (parseMultipart "XX" "--XX\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\nhello\r\n").2 == true
#guard (parseMultipart "XX" "junk\r\n--XX\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\nhello\r\n--XX--\r\n").2 == true
#guard headerParam "multipart/form-data; boundary=\"XX\"" "boundary" == some "XX"
#guard headerParam "multipart/form-data; boundary=XX" "boundary" == some "XX"
#guard (let s := phase2Store { requestBodyAccess := true } { method := "POST", uri := "/", headers := [("Content-Type", "multipart/form-data; boundary=XX")], body := some mpBody } true none false (phase1Store {} { uri := "/" })
        ((s.get "ARGS_POST").map (fun m => (m.key, ofBytes m.value)), (s.get "FILES").map (fun m => (m.key, ofBytes m.value)), (s.get "FILES_NAMES").map (ofBytes ·.value),
         (s.get "FILES_COMBINED_SIZE").map (ofBytes ·.value), (s.get "MULTIPART_STRICT_ERROR").map (ofBytes ·.value), (s.get "REQBODY_PROCESSOR").map (ofBytes ·.value), (s.get "REQUEST_BODY").length))
  == ([("t", "hello")], [("f", "a.txt")], ["f"], ["3"], ["0"], ["MULTIPART"], 0)
#guard ((phase2Store { requestBodyAccess := true } { method := "POST", uri := "/", headers := [("Content-Type", "multipart/form-data; boundary=XX")], body := some mpBody } true none false (phase1Store {} { uri := "/" })).get "MULTIPART_PART_HEADERS").map (fun m => (m.key, (ofBytes m.value).startsWith "Content-Disposition")) == [("t", true), ("f", true)]

end SecLang
