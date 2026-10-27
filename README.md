# Getting started
Install radare2 and adb and make sure the commands are available in your $PATH

```
python3 -m venv venv
source venv/bin/activate
python3 apk-miner.py -h
```

list matching packages installed on your phone

`python3 android_apk_downloader.py --start-date "2026-10-25" --end-date "2026-10-26" --find-apks`

list and download all matching packages installed on your phone

`python3 android_apk_downloader.py --start-date "2026-10-25" --end-date "2026-10-26" --find-apks --download-apks`

list, download and perform static analyis/secrets extraction for all matching packages installed on your phone

`python3 android_apk_downloader.py --start-date "2026-10-25" --end-date "2026-10-26" --find-apks --download-apks --analyze-apks`

show all findings stored in the sqlite database

`python3 android_apk_downloader.py --search-findings`

show all findings stored in the sqlite database that match your search string

`python3 android_apk_downloader.py --search-findings "PRIVATE KEY"`


