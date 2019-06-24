import * as OnLoadInterceptor from "frida-onload";

OnLoadInterceptor.attach((modulePath: string, base: NativePointer) => {
    console.log('hit module loading! @name ' + modulePath + ' @' + base);
});
