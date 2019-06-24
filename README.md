# Frida onload

A frida module to get a callback when module are being initialized.

Only for android at the moment

## install

```$xslt
git clone https://github.com/iGio90/frida-onload.git
npm install
npm link
```

### try it out
```$xslt
cd example
npm link frida-onload
npm install
npm run watch

# make your edits to index.ts
# inject the agent (quick att.py)
```

example code
```typescript
import * as OnLoadInterceptor from "frida-onload";

OnLoadInterceptor.attach((modulePath: string, base: NativePointer) => {
    console.log('hit module loading! @name ' + modulePath + ' @' + base);
});
```

## changelog

**2019.06.24**
```
* push
```

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