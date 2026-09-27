# mås
mås - A file upload-to-disk server written in golang

## About
I had to write for many reasons but mainly because memory management 
is a problem in a lot of languages before writing to disk (I'm looking at you, Rack)

**JWT for authentication**. The JWT claims should be:
```
{ "role": "some role" }
```

where `some role` is passed as a parameter to **mås**

... I'll finish documenting this later. Look at the `main()` function.

## S3 upload

Pass `-s3` to enable uploading finished files to S3, and `-s3config` to point
at a JSON file shaped like `maas-s3.json.example`. That file is re-read on
every upload, so rotating credentials only means editing it — no rebuild or
restart needed.
