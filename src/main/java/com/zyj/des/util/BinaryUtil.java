package com.zyj.des.util;

public class BinaryUtil {
    //StringBuffer转成二进制
    public static StringBuffer stringBufferToBinary(StringBuffer s) {
        StringBuffer res = new StringBuffer();
        s.toString().codePoints().forEach(item -> {
            StringBuffer stmp = new StringBuffer(Integer.toBinaryString(item));
            // 补充前导0
            while (stmp.length() < 8) {
                stmp.insert(0, 0);
            }
            res.append(stmp);
        });
        return res;
    }

    //二进制字符串转成字符64->8
    //int column = Integer.parseInt(Sinput.substring(1, 5), 2);
    public static StringBuffer BinaryTostringBuffer(StringBuffer s) {
        StringBuffer res = new StringBuffer();
        for (int i = 0; i < 8; i++) {
            int t = Integer.parseInt(s.substring(i * 8, (i + 1) * 8), 2);
            res.append((char) t);
        }
        return res;
    }
}
