# Google Maps API Checker

A small tool for checking Google Maps REST services. Runs on your computer, opens in your browser. Python 3.9+ required. Nothing else to install.

## Getting started

```
python3 app.py
```

Visit http://127.0.0.1:8765

Paste your key, pick some services, click **Check services**. Results can be saved as JSON. Press Ctrl+C in the terminal to quit.

Need another port? `python3 app.py --port 9000`

## Android keys

Choose **Android (REST test)**. Enter the package name and signing certificate SHA-1.

Find your SHA-1 with `./gradlew signingReport`. For Google Play builds, use the app signing certificate, not the upload certificate.

This tests REST requests only. It cannot confirm a package/SHA-1 match or test Maps SDK for Android. Check those in your Android app.

## Please note

- Google may charge for test requests.
- Use only keys you own or have permission to test.
- Keys go to Google, but are not saved by this tool or included in exports.
- Keep this server local. Keep your key restrictions enabled.
- Results are not a complete list of enabled APIs. Check Google Cloud Console for that.

## Testing

```
python3 -m unittest -v
```
