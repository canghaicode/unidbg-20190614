package cn.banny.unidbg.spi;

import cn.banny.unidbg.Emulator;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface LibraryFile {

    String getName();

    String getMapRegionName();

    LibraryFile resolveLibrary(Emulator emulator, String soName) throws IOException;

    byte[] readToByteArray() throws IOException;

    ByteBuffer mapBuffer() throws IOException;

    String getPath();

}
