package cn.banny.unidbg.hook.xhook;

import cn.banny.unidbg.hook.IHook;
import cn.banny.unidbg.hook.ReplaceCallback;

/**
 * Only support android
 */
public interface IxHook extends IHook {

    int RET_SUCCESS = 0;

    void register(String pathname_regex_str, String symbol, ReplaceCallback callback);

    void refresh();

}
