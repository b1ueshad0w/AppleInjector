# Overview

With this script you can do 2 powerful things:

- Inject a __dylib__ or __framework__ to an iOS bundle
- Re-codesigning an iOS bundle

> iOS bundle could be .ipa/.app/.framework files.

# Usage

## Re-codesigning

Re-codesigning:

```shell
python recodesign.py \
	-a /path/to/your/app \
	-o /path/to/new/app \
	-c "CODE_SIGNING_IDENTITY" \
	-p /path/to/mobileprovisionfile
```

For example:

```shell
python recodesign.py \
	-a MyDemo.ipa \
	-o MyDemoNew.ipa \
	-c "iPhone Developer: XXX (XXXXX)" \
	-p my.mobileprovision
```

## Injection

Injection. You can inject either __dylib__ or __framework__ to your app.

```shell
python recodesign.py \
	-a /path/to/your/app \
	-o /path/to/new/app \
	-c "CODE_SIGNING_IDENTITY" \
	-p /path/to/mobileprovisionfile \
	-d /path/to/fileForInjection
```

For example:

```Shell
python recodesign.py \
	-a MyDemo.ipa \
	-o MyDemoNew.ipa \
	-c "iPhone Developer: XXX (XXXXX)" \
	-p my.mobileprovision \
	-d hook.dylib
```



Enjoy it.