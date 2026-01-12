package com.zyj.des;

import com.zyj.des.core.DesCipher;

import static com.zyj.des.util.BinaryUtil.BinaryTostringBuffer;
import static com.zyj.des.util.BinaryUtil.stringBufferToBinary;

public class Main {
    public static void main(String[] args) {
        StringBuffer plain = new StringBuffer("hello world"); //录入明文
        int length = plain.length(); //保存明文的长度
        StringBuffer secretKey = new StringBuffer("123456");
        DesCipher desCipher = new DesCipher(plain,secretKey);
        System.out.println("明文：" + desCipher.getPlaintext());
        System.out.println("密钥：" + desCipher.getKey());

        //测试加密
        System.out.println("-----DES加密-----");
        plain = stringBufferToBinary(desCipher.getPlaintext()); //明文转成二进制
        StringBuffer L = new StringBuffer();//左明文
        StringBuffer R = new StringBuffer();//右明文
        StringBuffer plainBackup = new StringBuffer(plain);  //二进制明文备份
        StringBuffer cipherBackup = new StringBuffer();  //二进制密文备份
        StringBuffer descipher = new StringBuffer(); //解密后的明文
        //扩充明文
        while (plainBackup.length() < 64 * (desCipher.getGroup() + 1)) {
            plainBackup.append("0");
        }
        //分组加密
        for (int i = 0; i <= desCipher.getGroup(); i++) {
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
            System.out.println(i + "轮迭代后：" + plain);

            //备份二进制密文
            cipherBackup.append(plain);
            System.out.println(i + "轮密文：" + BinaryTostringBuffer(plain));
        }

        //测试解密
        System.out.println("-----DES解密-----");
        //分组解密
        for (int i = 0; i <= desCipher.getGroup(); i++) {
            //密文分组处理
            for (int j = 0; j < 64; j++) {
                plain.replace(j, j + 1, cipherBackup.substring(j + i * 64, j + 64 * i + 1));
            }

            //初始置换
            plain = desCipher.getDesStage().initial(plain);

            L.replace(0, 32, plain.substring(0, 32));
            R.replace(0, 32, plain.substring(32, 64));
            plain = desCipher.getDesStage().iteration(L, R, 1);//plain是解密后的二进制密文
            System.out.println(i + "轮迭代后：" + plain);
            System.out.println(i + "明文：" + BinaryTostringBuffer(plain));
            descipher.append(BinaryTostringBuffer(plain));
        }
        //输出解密后的明文
        System.out.println("最终解密后的明文："+descipher.substring(0,length));
    }
}
