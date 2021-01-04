# frida-onload

A Frida module to execute a callback when a native library or a Java class gets loaded (also async). It works on Android
 and
 Windows.

## Installation

```$xslt
git clone https://github.com/iGio90/frida-onload.git
npm install
npm link
```

## Usage

Use callbacks if you want to execute hot stuff before the module initializes something (e.g. `DT_INIT`, `DT_INIT_ARRAY
` on
 Android):
```typescript
// callbacks.ts
import "frida-onload";

Module.onLoad("mymodule.so", (module: Module, wasAlreadyLoaded: boolean) => {
    if (!wasAlreadyLoaded) {
        doFancyStuff(module);
    } else {
        console.log("Library was already loaded. Skipping...");
    }
});
```

Otherwise, if you are an `async` person:
```typescript
// async.ts
import "frida-onload";

async function main() {
    const library = await Module.waitFor("MyAssembly.dll");
    console.log("Assembly has been loaded!");

    await doFancyStuff(library);
}

main().catch(e => console.log(e.stack));
```

If you need to wait for a Java class to be created:
```typescript
// async.ts
import "frida-onload";

Java.performNow(() => {
    async function main() {
        const sneakyClass = await Java.waitFor("org.external.loaded.class");
        if (sneakyClass != null) {
            sneakyClass.sneakyMethod.overload().implementation = function () {
                console.log("I got you!");
                return this.sneakyMethod();
            };
        }
    }

    main().catch(e => console.log(e.stack));
});
```

## Changelog

**2021.01.04**
* Added `async` support
* Frida's `Module` and `Java` namespaces are extended instead of having a brand new module
* (Android) Hooking the native method `soinfo::get_realpath` instead of `soinfo::call_constructor` and `linker::do_dlopen`
* (Java) Hooking the native method `defineClassNative` instead of `java.lang.ClassLoader.loadClass`

**2019.06.28**
* Added support for Windows module loading: thanks @PinkiePieStyle
* Added support for Java ClassLoader loading class

**2019.06.24**
* Push

---

```
Copyright (c) 2019 Giovanni (iGio90) Rocca

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```