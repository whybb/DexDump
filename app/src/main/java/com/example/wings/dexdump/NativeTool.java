package com.example.wings.dexdump;

/**
 * Created by wings on 2016/12/19.
 */
public class NativeTool
{
    static
    {
        System.loadLibrary("native-lib");
    }

    public native static int Dump(String str);
    public  native static String stringFromJNI();

    public native static int DumpDex(String name);
}
