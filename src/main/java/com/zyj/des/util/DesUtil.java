package com.zyj.des.util;

import com.zyj.des.core.DesCipher;

import static com.zyj.des.util.BinaryUtil.BinaryTostringBuffer;
import static com.zyj.des.util.BinaryUtil.stringBufferToBinary;

public class DesUtil {
    public static String encrypt(String plaintext, String key) {
        return encrypt(new DesCipher(plaintext, key));
    }

    public static String encrypt(DesCipher desCipher) {
        StringBuffer plain = stringBufferToBinary(desCipher.getPlaintext()); //明文转成二进制
        StringBuffer L = new StringBuffer();//左明文
        StringBuffer R = new StringBuffer();//右明文
        StringBuffer plainBackup = new StringBuffer(plain);  //二进制明文备份
        StringBuffer cipherBackup = new StringBuffer();  //二进制密文备份
        //分组加密
        for (int i = 0; i <= desCipher.getGroupCount(); i++) {
            //明文分组处理
            for (int j = 0; j < 64; j++) {
                plain.replace(j, j + 1, plainBackup.substring(j + i * 64, j + 64 * i + 1));
            }
            //初始置换
            plain = desCipher.getDesStage().initial(plain);
            L.replace(0, 32, plain.substring(0, 32));
            R.replace(0, 32, plain.substring(32, 64));
            //16轮迭代
            plain = desCipher.getDesStage().iteration(L, R, 0);//plain是加密后的二进制密文
            //备份二进制密文
            cipherBackup.append(plain);
        }
        return cipherBackup.toString();
    }

    public static String decrypt(String ciphertext, String secretKey) {
        StringBuffer plain = new StringBuffer(ciphertext);
        StringBuffer L = new StringBuffer();//左明文
        StringBuffer R = new StringBuffer();//右明文
        StringBuffer descipher = new StringBuffer();
        //分组解密
        for (int i = 0; i <= 1; i++) {
            //密文分组处理
            for (int j = 0; j < 64; j++) {
                plain.replace(j, j + 1, ciphertext.substring(j + i * 64, j + 64 * i + 1));
            }
            //初始置换
            DesCipher.DesStage desStage = new DesCipher.DesStage(secretKey);
            plain = desStage.initial(plain);
            L.replace(0, 32, plain.substring(0, 32));
            R.replace(0, 32, plain.substring(32, 64));
            plain = desStage.iteration(L, R, 1);// plain是解密后的二进制密文
//            System.out.println(i + "明文：" + BinaryTostringBuffer(plain));
            descipher.append(BinaryTostringBuffer(plain));
        }
        return descipher.toString();
    }
}
