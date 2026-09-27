package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/cristalhq/jwt/v5"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

type arrayFlag []string

type fileinfo struct {
	Name     string `json:"name"`
	Checksum string `json:"checksum"`
	Size     int64  `json:"size"`
	Path     string `json:"path"`
}

type userclaims struct {
	Role string `json:"role"`
}

func (i *arrayFlag) String() string {
	return strings.Join(*i, ",")
}

func (i *arrayFlag) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	logfile *os.File
	logbuf  bytes.Buffer
	logger  = log.New(&logbuf, "", log.LstdFlags)
)

var (
	unixsocket string

	dir    string
	tmpdir string

	secretkey  string
	pubkeyfile string
	pubkey     *rsa.PublicKey
	roles      arrayFlag

	verifier jwt.Verifier

	s3           bool
	s3configpath string
)

var form_template = `<!DOCTYPE html>
<html>
  <head>
    <title>File Upload</title>
  </head>

  <body>
    <form method="post" action="/" enctype="multipart/form-data">
      <fieldset>
        <input type="text"
               name="filename"
               placeholder="filename"
               required>

        <input type="file"
               name="file"
               multiple="multiple">

        <input type="submit"
               value="Upload">
      </fieldset>
    </form>

    <hr>

    <form method="post" action="/">
      <fieldset>
        <input type="text"
               name="filename"
               placeholder="filename"
               required>

        <input type="text"
               name="location"
               placeholder="http://example.org/image.png">

        <input type="submit"
               value="Upload">
      </fieldset>
    </form>
  </body>
</html>
`

type handler func(w http.ResponseWriter, r *http.Request)

func jwt_check(fn handler) handler {
	return func(w http.ResponseWriter, r *http.Request) {
		auth_header := r.Header.Get("Authorization")

		if auth_header == "" {
			fmt.Println("No Authorization header")
			http.Error(w, "No Authorization header", http.StatusUnauthorized)
			return
		}

		token, err := parsetoken(strings.TrimPrefix(auth_header, "Bearer "))
		if err != nil {
			fmt.Println("parse token bearer")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var claims userclaims
		err = json.Unmarshal(token.Claims(), &claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if slices.Contains(roles, "*") {
			fn(w, r)
			return
		}

		for _, ro := range roles {
			if ro == claims.Role {
				fn(w, r)
				return
			}
		}

		fmt.Println("roles... aunthorerized")

		http.Error(w, "Wrong role claim", http.StatusUnauthorized)
	}
}

func uri_check(url string) (status int, success bool) {
	if !strings.HasPrefix(url, "http") {
		success = false
		status = http.StatusBadRequest
		return
	}

	resp, err := http.Head(url)
	if err != nil {
		log.Fatal(err)
	}

	success = (resp.StatusCode == http.StatusOK)
	status = resp.StatusCode
	return
}

func file_insert(dest *os.File, stream io.Reader) (err error) {
	if _, err = io.Copy(dest, stream); err != nil {
		return err
	}

	return
}

func catch(r *http.Request) (fpath string, err error) {
	var fname string

	reader, err := r.MultipartReader()
	if err != nil {
		return
	}

	tmpfile, err := ioutil.TempFile(tmpdir, "maas-*")
	defer tmpfile.Close()

	r.ParseMultipartForm(0)

	for {
		part, e := reader.NextPart()

		if e == io.EOF {
			break
		}

		if part.FormName() == "file" && part.FileName() != "" {
			err = file_insert(tmpfile, part)
			if err != nil {
				return
			}
		}

		if part.FormName() == "filename" {
			buf := new(bytes.Buffer)
			buf.ReadFrom(part)
			fname = buf.String()
		}
	}

	if fname == "" {
		os.Remove(tmpfile.Name())
		return

	} else {
		fpath = dir + "/" + fname
		err = os.Rename(tmpfile.Name(), fpath)
	}

	return fpath, err
}

func snatch(r *http.Request) (fname string, err error) {
	r.ParseForm()

	location := r.FormValue("location")

	fname = r.FormValue("filename")

	if location == "" {
		err = errors.New("'location' value is not present")
		return
	}

	if fname == "" {
		err = errors.New("'filename' value is not present")
		return
	}

	if status, ok := uri_check(location); !ok {
		err = errors.New("Couldn't... I got '" + (strconv.Itoa(status)) + "' status code. :(")
		return
	}

	resp, err := http.Get(location)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	tmpfile, _ := ioutil.TempFile(dir, fname)
	defer tmpfile.Close()

	err = file_insert(tmpfile, resp.Body)
	if err != nil {
		return
	}

	return
}

func read_request(w http.ResponseWriter, r *http.Request) {
	var fname string
	var err error

	switch r.Method {
	case "OPTIONS":
		w.Header().Set("Allow", "POST,GET")
		w.WriteHeader(http.StatusOK)

	case "GET":
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(form_template))

	case "POST":
		w.Header().Add("Content-Type", "application/json")

		drop := func(e error) {
			http.Error(w, e.Error(), http.StatusInternalServerError)
			logger.Println(e.Error())
		}

		if t := r.Header.Get("Content-Type"); strings.HasPrefix(t, "multipart/form-data") {
			fname, err = catch(r)
			if err != nil {
				drop(err)
				return
			}
		} else {
			fname, err = snatch(r)
			if err != nil {
				drop(err)
				return
			}
		}

		f, err := os.Stat(fname)
		if err != nil {
			drop(err)
			return
		}

		file, err := os.Open(fname)
		if err != nil {
			drop(err)
			return
		}

		chksum := md5.New()
		if _, err := io.Copy(chksum, file); err != nil {
			drop(err)
			return
		}

		md5sum := chksum.Sum(nil)
		md5str := fmt.Sprintf("%x", md5sum)
		md5base64 := base64.StdEncoding.EncodeToString(md5sum)

		var path string

		if s3 {
			if path, err = s3put(fname, md5base64, s3configpath); err != nil {
				drop(err)
				return
			}
		}

		j, _ := json.Marshal(fileinfo{filepath.Base(fname), md5str, f.Size(), path})

		w.Write([]byte(j))

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func arguments() {
	flag.StringVar(&unixsocket, "unixsocket", "/tmp/mås-server.sock", "UNIX socket to listen to")

	flag.StringVar(&dir, "dir", ".", "Directory where uploads should be finally stored")
	flag.StringVar(&tmpdir, "tmpdir", ".", "Directory where uploads should be stored whilst uploading")

	flag.StringVar(&secretkey, "secretkey", "", "Secret key verify JWT's")

	flag.StringVar(&pubkeyfile, "pubkeyfile", "", "Public key to verify JWT's")
	flag.Var(&roles, "role", "Roles permitted in the JWT claims")

	flag.BoolVar(&s3, "s3", false, "Whether to upload files to S3")
	flag.StringVar(&s3configpath, "s3config", "/etc/maas-s3.json", "Path to a JSON file with S3 credentials ({key, secret, provider, bucket, directory, acl}). Re-read on every upload, so rotating the key needs no rebuild or restart.")

	flag.Parse()

	fmt.Println("Destination is:", dir)
	fmt.Println("Temporary directory is:", tmpdir)

	fmt.Println("UNIX socket:", unixsocket)

	if pubkeyfile != "" {
		fmt.Println("Public key:", pubkeyfile)
		fmt.Println("Accepted roles:", roles)
	} else if secretkey != "" {
		fmt.Println("Secret key:", secretkey)
		fmt.Println("Accepted roles:", roles)
	} else {
		log.Fatal(errors.New("I won't start without secretkey/pubkeyfile!"))
	}

	if s3 {
		conf, err := s3config_get(s3configpath)
		if err != nil {
			panic(fmt.Sprintf("Can't read s3config '%s': %s", s3configpath, err.Error()))
		}

		fmt.Println("Will put files into S3, config:", s3configpath)
		fmt.Println("\tprovider:", conf.Provider)
		fmt.Println("\tbucket:", conf.Bucket)
		fmt.Println("\tdirectory:", conf.Directory)
		fmt.Println("\tacl:", conf.ACL)
	}
}

func run_serve(fn func(handler) handler) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", fn(read_request))

	l, err := net.Listen("unix", unixsocket)
	if err != nil {
		panic(err)
	}
	defer l.Close()

	os.Chmod(unixsocket, 0777)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL)

	go func() {
		<-c
		l.Close()
	}()

	fmt.Println("Listening...")

	panic(http.Serve(l, mux))
}

func main() {
	arguments()

	logfile, _ = os.OpenFile("/var/log/mås.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)

	d, err := os.Open(dir)
	if err != nil {
		log.Fatal(errors.New("Specified directory does not exist!"))
	}
	d.Close()

	t, err := os.Open(tmpdir)
	if err != nil {
		log.Fatal(errors.New("Specified temporary directory does not exist!"))
	}
	t.Close()

	if pubkeyfile != "" && secretkey != "" {
		panic("both pubkey and secretkey given... no no.")
	}

	if pubkeyfile != "" {
		verifier, err = jwt.NewVerifierRS(jwt.RS256, parsepubkey())
	}

	if secretkey != "" {
		verifier, err = jwt.NewVerifierHS(jwt.HS256, []byte(secretkey))
	}

	if err != nil {
		panic(err)
	}

	run_serve(jwt_check)
}

func parsepubkey() *rsa.PublicKey {
	b, err := ioutil.ReadFile(pubkeyfile)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(b)
	if block == nil {
		panic("invalid PEM")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return key.(*rsa.PublicKey)
}

func parsetoken(s string) (token *jwt.Token, err error) {
	if token, err = jwt.Parse([]byte(s), verifier); err != nil {
		return nil, err
	}

	if verifier.Verify(token); err != nil {
		return nil, err
	}

	return
}
