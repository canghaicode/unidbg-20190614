package cn.banny.unidbg.pointer;

import cn.banny.unidbg.AbstractEmulator;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

public abstract class UnicornStructure extends Structure {

    /** Placeholder pointer to help avoid auto-allocation of memory where a
     * Structure needs a valid pointer but want to avoid actually reading from it.
     */
    private static final Pointer PLACEHOLDER_MEMORY = new Pointer(0) {
        @Override
        public Pointer share(long offset, long sz) { return this; }
    };

    public static int calculateSize(Class<? extends UnicornStructure> type) {
        try {
            Constructor<? extends UnicornStructure> constructor = type.getConstructor(Pointer.class);
            return constructor.newInstance(PLACEHOLDER_MEMORY).calculateSize(false);
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw new IllegalStateException(e);
        }
    }

    protected UnicornStructure(Pointer p) {
        super(p);

        checkPointer(p);
    }

    private void checkPointer(Pointer p) {
        if (p == null) {
            throw new NullPointerException("p is null");
        }
        if (!(p instanceof UnicornPointer) && !isPlaceholderMemory(p)) {
            throw new IllegalArgumentException("p is NOT UnicornPointer");
        }
    }

    @Override
    protected int getNativeSize(Class<?> nativeType, Object value) {
        if (Pointer.class.isAssignableFrom(nativeType)) {
            return AbstractEmulator.POINTER_SIZE.get();
        }

        return super.getNativeSize(nativeType, value);
    }

    @Override
    protected int getNativeAlignment(Class<?> type, Object value, boolean isFirstElement) {
        if (Pointer.class.isAssignableFrom(type)) {
            return AbstractEmulator.POINTER_SIZE.get();
        }

        return super.getNativeAlignment(type, value, isFirstElement);
    }

    private boolean isPlaceholderMemory(Pointer p) {
        return "native@0x0".equals(p.toString());
    }

    public void pack() {
        super.write();
    }

    public void unpack() {
        super.read();
    }

}
