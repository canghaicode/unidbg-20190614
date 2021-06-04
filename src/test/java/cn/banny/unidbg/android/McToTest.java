package cn.banny.unidbg.android;

import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.arm.ARM;
import cn.banny.unidbg.linux.android.AndroidResolver;
import unicorn.Unicorn;

import java.io.File;

public class McToTest extends EmulatorTest {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new AndroidResolver(19);
    }

    public void testMcTo() throws Exception {
        long start = System.currentTimeMillis();
        emulator.getMemory().setCallInitFunction();
        Unicorn unicorn = emulator.getUnicorn();
        Module module = emulator.loadLibrary(new File("src/test/resources/mcto/libmcto_media_player.so"));
        System.err.println("load offset=" + (System.currentTimeMillis() - start) + "ms");
        start = System.currentTimeMillis();
        // emulator.traceCode();
        Number[] numbers = module.callFunction(emulator, 0x249bc8 + 1, "/vps?tvid=11949478009&vid=7b23569cbed511dd58bcd6ce9ddd7b42&v=0&qypid=11949478009_unknown&src=02022001010000000000&tm=1519712402&k_tag=1&k_uid=359125052784388&bid=1&pt=0&d=1&s=0&rs=1&dfp=1413357b5efa4a4130b327995c377ebb38fbd916698ed95a28f56939e9d8825592&k_ver=9.0.0&k_ft1=859834543&k_err_retries=0&qd_v=1");
        long address = numbers[0].intValue() & 0xffffffffL;
        System.out.println("ret=" + ARM.readCString(unicorn, address));
        System.err.println("eFunc offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
