package com.zyj.des.util;

public class TripleDesUtil {
    public static String encrypt(String plainText, String key1, String key2, String key3) {
        return DesUtil.encrypt(DesUtil.decrypt(DesUtil.encrypt(plainText, key1), key2), key3);
    }

    public static String decrypt(String cipherText, String key1, String key2, String key3) {
        return DesUtil.decrypt(DesUtil.encrypt(DesUtil.decrypt(cipherText, key3), key2), key1);
    }
}
