# Frida onload

A frida module to quickly hook at native module initialization.

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
import {OnLoadInterceptor} from "frida-onload";

OnLoadInterceptor.attach('libtarget.so', (modulePath: string, base: NativePointer) => {
    console.log('hit module loading! @' + base);
});
```

## changelog

**2019.06.24**
```
* push
```

---

```
Frida onload) - Copyright (C) 2019 Giovanni (iGio90) Rocca

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>
```