package cn.banny.unidbg.linux.file;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.unix.UnixEmulator;
import cn.banny.unidbg.unix.file.LocalUdpSocket;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class LocalAndroidUdpSocket extends LocalUdpSocket {

    private static final Log log = LogFactory.getLog(LocalAndroidUdpSocket.class);

    public LocalAndroidUdpSocket(Emulator emulator) {
        super(emulator);
    }

    @Override
    protected int connect(String path) {
        switch (path) {
            case "/dev/socket/logdw":
                handler = new UdpHandler() {
                    private static final int LOG_ID_MAIN = 0;
                    private static final int LOG_ID_RADIO = 1;
                    private static final int LOG_ID_EVENTS = 2;
                    private static final int LOG_ID_SYSTEM = 3;
                    private static final int LOG_ID_CRASH = 4;
                    private static final int LOG_ID_KERNEL = 5;
                    private final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    @Override
                    public void handle(byte[] request) {
                        try {
                            byteArrayOutputStream.write(request);

                            if (byteArrayOutputStream.size() <= 11) {
                                return;
                            }

                            int tagIndex = -1;
                            int bodyIndex = -1;
                            byte[] body = byteArrayOutputStream.toByteArray();
                            ByteBuffer buffer = ByteBuffer.wrap(body);
                            buffer.order(ByteOrder.LITTLE_ENDIAN);
                            int id = buffer.get() & 0xff;
                            int tid = buffer.getShort() & 0xffff;
                            int tv_sec = buffer.getInt();
                            int tv_nsec = buffer.getInt();
                            log.debug("handle id=" + id + ", tid=" + tid + ", tv_sec=" + tv_sec + ", tv_nsec=" + tv_nsec);

                            String type;
                            switch (id) {
                                case LOG_ID_MAIN:
                                    type = "main";
                                    break;
                                case LOG_ID_RADIO:
                                    type = "radio";
                                    break;
                                case LOG_ID_EVENTS:
                                    type = "events";
                                    break;
                                case LOG_ID_SYSTEM:
                                    type = "system";
                                    break;
                                case LOG_ID_CRASH:
                                    type = "crash";
                                    break;
                                case LOG_ID_KERNEL:
                                    type = "kernel";
                                    break;
                                default:
                                    type = Integer.toString(id);
                                    break;
                            }

                            for (int i = 12; i < body.length; i++) {
                                if (body[i] != 0) {
                                    continue;
                                }

                                if (tagIndex == -1) {
                                    tagIndex = i;
                                    continue;
                                }

                                bodyIndex = i;
                                break;
                            }

                            if (tagIndex != -1 && bodyIndex != -1) {
                                byteArrayOutputStream.reset();

                                int level = body[11] & 0xff;
                                String tag = new String(body, 12, tagIndex - 12);
                                String text = new String(body, tagIndex + 1, bodyIndex - tagIndex - 1);
                                final String c;
                                switch (level) {
                                    case LogCatFileIO.VERBOSE:
                                        c = "V";
                                        break;
                                    case LogCatFileIO.DEBUG:
                                        c = "D";
                                        break;
                                    case LogCatFileIO.INFO:
                                        c = "I";
                                        break;
                                    case LogCatFileIO.WARN:
                                        c = "W";
                                        break;
                                    case LogCatFileIO.ERROR:
                                        c = "E";
                                        break;
                                    case LogCatFileIO.ASSERT:
                                        c = "A";
                                        break;
                                    default:
                                        c = level + "";
                                        break;
                                }
                                System.err.println(String.format("[%s]%s/%s: %s", type, c, tag, text));
                            }
                        } catch (IOException e) {
                            throw new IllegalStateException(e);
                        }
                    }
                };
                return 0;
        }

        emulator.getMemory().setErrno(UnixEmulator.EPERM);
        return -1;
    }

}
