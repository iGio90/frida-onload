import {OnLoadInterceptor} from "frida-onload";

OnLoadInterceptor.attach((modulePath: string, base: NativePointer) => {
    console.log('hit module loading! @name ' + modulePath + ' @' + base);
});

OnLoadInterceptor.attachJava((clazz: string) => {
    console.log('hit java class loader! @' + clazz)
});
