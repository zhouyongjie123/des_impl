package com.zyj.des;
import lombok.Getter;
import lombok.Setter;

import java.util.Scanner;

import static com.zyj.des.core.Constant.*;
import static com.zyj.des.util.BinaryUtil.BinaryTostringBuffer;
import static com.zyj.des.util.BinaryUtil.stringBufferToBinary;

public class Demo {
    @Setter
    @Getter
    private StringBuffer plaintext;  //明文字符串64 bits----8 bytes
    @Setter
    @Getter
    private StringBuffer ciphertext;  //密文字符串64 bits----8 bytes
    @Setter
    @Getter
    private StringBuffer key;  //密钥字符串64 bits ----8 bytes
    private int group;  //分组

    //设置分组数
    public void setGroup() {
        group = plaintext.length() / 8;
    }

    //初始置换IP
    public StringBuffer Initial(StringBuffer r) {
        StringBuffer res = new StringBuffer();
        for (int i = 0; i < 64; i++) {
            res.append(r.charAt(IP[i] - 1)); //数组的索引是从0开始的
        }
        return res;
    }

    //终止置换IP
    public StringBuffer Final(StringBuffer r) {
        StringBuffer res = new StringBuffer();
        for (int i = 0; i < 64; i++) {
            res.append(r.charAt(IPReverse[i] - 1)); //数组的索引是从0开始的
        }
        return res;
    }

    //P置换
    public StringBuffer P(StringBuffer r) {
        StringBuffer res = new StringBuffer();
        for (int i = 0; i < 32; i++) {
            res.append(r.charAt(P[i] - 1)); //数组的索引是从0开始的
        }
        return res;
    }

    //扩展置换（E表）
    public StringBuffer Extent(StringBuffer r) {
        StringBuffer res = new StringBuffer();
        for (int i = 0; i < 48; i++) {
            res.append(r.charAt(E[i] - 1)); //数组的索引是从0开始的
        }
        return res;
    }

    //密钥生成
    public StringBuffer[] getSubkey() {
        StringBuffer keyBinary = new StringBuffer(stringBufferToBinary(key)); //把密钥转成二进制
        StringBuffer subkey[] = new StringBuffer[16];  //subkey数组用来存储子密钥
        StringBuffer C0 = new StringBuffer(); //左密钥
        StringBuffer D0 = new StringBuffer(); //右密钥
        //判断密钥长度
        while (keyBinary.length() < 64) {
            keyBinary.append("0");
        }
        //PC1置换（64 bits --> 56 bits）
        for (int i = 0; i < 28; i++) {
            C0.append(keyBinary.charAt(PC1[i] - 1));
            D0.append(keyBinary.charAt(PC1[i + 28] - 1));
        }
        //16轮循环生成子密钥
        //16轮移位操作，每轮左移一位，特殊情况左移两位（查看密钥移位表）
        for (int i = 0; i < 16; i++) {
            //把第一位删了添加到最后一位
            char tmp;
            tmp = C0.charAt(0);
            C0.deleteCharAt(0);
            C0.append(tmp);
            tmp = D0.charAt(0);
            D0.deleteCharAt(0);
            D0.append(tmp);
            //特殊位置左移两位
            if (i != 0 && i != 1 && i != 8 && i != 15) {
                tmp = C0.charAt(0);
                C0.deleteCharAt(0);
                C0.append(tmp);
                tmp = D0.charAt(0);
                D0.deleteCharAt(0);
                D0.append(tmp);
            }
            //左右合并
            StringBuffer CODO = new StringBuffer(C0.toString() + D0.toString());
            //PC2置换
            StringBuffer C0D0tmp = new StringBuffer();
            for (int j = 0; j < 48; j++) {
                C0D0tmp.append(CODO.charAt(PC2[j] - 1));
            }
            subkey[i] = C0D0tmp;
            //  System.out.println(i + "轮密钥：" + subkey[i]);
        }
        return subkey;
    }

    //f轮函数
    public StringBuffer F(StringBuffer R, StringBuffer subkey) {
        StringBuffer res = new StringBuffer();
        //E盒扩展
        res = Extent(R);
        //异或运算
        for (int i = 0; i < 48; i++) {
            res.replace(i, i + 1, (res.charAt(i) == subkey.charAt(i) ? "0" : "1"));
        }
        //S盒压缩
        StringBuffer sBox = new StringBuffer();  //sBox用来接收压缩后的32 bits
        for (int i = 0; i < 8; i++) {
            String Sinput = res.substring(i * 6, (i + 1) * 6);
            //首尾两位转化为行，中间四位转化为列
            //parseInt(String s,int radix)---把字符串s根据radix（进制）转成对应的整数
            int row = Integer.parseInt(Character.toString(Sinput.charAt(0)) + Sinput.charAt(5), 2);
            int column = Integer.parseInt(Sinput.substring(1, 5), 2);
            StringBuffer Soutput = new StringBuffer(Integer.toBinaryString(SBox[i][row * 16 + column]));
            while (Soutput.length() < 4) {//小于四位要添0
                Soutput.insert(0, 0);
            }
            sBox.append(Soutput);
        }
        //P置换
        sBox = P(sBox);
        return sBox;
    }

    //16轮迭代
    public StringBuffer iteration(StringBuffer L, StringBuffer R, int mode) {
        StringBuffer res = new StringBuffer();
        StringBuffer[] subkey = getSubkey(); //获取子密钥
        //mode == 1 解密  密钥反转
        if (mode == 1) {
            StringBuffer[] tmp = getSubkey();  //mode ==1
            for (int i = 0; i < 16; i++) {
                subkey[i] = tmp[15 - i];
                //  System.out.println(i+"轮密钥："+subkey[i]);
            }
        }

        //查看密钥
//        for (int i =0;i<16;i++){
//            System.out.println(i+"轮密钥："+subkey[i]);
//        }

        //16轮循环
        for (int i = 0; i < 16; i++) {
            StringBuffer Ltmp = new StringBuffer(L);
            StringBuffer Rtmp = new StringBuffer(R);

            //右边的赋给左边
            L.replace(0, 32, R.toString());
            //F轮函数
            StringBuffer Fstring = F(Rtmp, subkey[i]);

            //Fstring异或R
            for (int j = 0; j < 32; j++) {
                R.replace(j, j + 1, (Fstring.charAt(j) == Ltmp.charAt(j) ? "0" : "1"));
            }
        }

        //循环结束后左右交换
        StringBuffer RL = new StringBuffer(R.toString() + L.toString());

        //终止置换
        RL = Final(RL);
        return RL;
    }

    public static void main(String[] args) {
        System.out.println("----DES----");
        Demo instance = new Demo();//创建实例

        StringBuffer plain = new StringBuffer(); //录入明文
        String tmp = ""; //用来临时录入明文密文
        Scanner sc = new Scanner(System.in);
        System.out.println("请输入明文：");
        tmp = sc.next();
        plain.append(tmp);
        int length = plain.length(); //保存明文的长度
        instance.setPlaintext(plain);
        System.out.println("明文：" + instance.getPlaintext());

        //密钥产生
        System.out.println("输入密钥：");
        tmp = sc.next();
        StringBuffer mykey = new StringBuffer();
        mykey.append(tmp);
        instance.setKey(mykey);
        System.out.println("密钥：" + instance.getKey());

        //设置分组数
        instance.setGroup();

        //测试加密
        System.out.println("-----DES加密-----");
        plain = stringBufferToBinary(instance.getPlaintext()); //明文转成二进制
        StringBuffer L = new StringBuffer();//左明文
        StringBuffer R = new StringBuffer();//右明文
        StringBuffer plainBackup = new StringBuffer(plain);  //二进制明文备份
        StringBuffer cipherBackup = new StringBuffer();  //二进制密文备份
        StringBuffer descipher = new StringBuffer(); //解密后的明文
        //扩充明文
        while (plainBackup.length() < 64 * (instance.group + 1)) {
            plainBackup.append("0");
        }
        //分组加密
        for (int i = 0; i <= instance.group; i++) {
            //明文分组处理
            for (int j = 0; j < 64; j++) {
                plain.replace(j, j + 1, plainBackup.substring(j + i * 64, j + 64 * i + 1));
            }

            //初始置换
            plain = instance.Initial(plain);

            L.replace(0, 32, plain.substring(0, 32));
            R.replace(0, 32, plain.substring(32, 64));

            //16轮迭代
            plain = instance.iteration(L, R, 0);//plain是加密后的二进制密文
            System.out.println(i + "轮迭代后：" + plain);

            //备份二进制密文
            cipherBackup.append(plain);
            System.out.println(i + "轮密文：" + BinaryTostringBuffer(plain));
        }

        //测试解密
        System.out.println("-----DES解密-----");
        //分组解密
        for (int i = 0; i <= instance.group; i++) {
            //密文分组处理
            for (int j = 0; j < 64; j++) {
                plain.replace(j, j + 1, cipherBackup.substring(j + i * 64, j + 64 * i + 1));
            }

            //初始置换
            plain = instance.Initial(plain);

            L.replace(0, 32, plain.substring(0, 32));
            R.replace(0, 32, plain.substring(32, 64));
            plain = instance.iteration(L, R, 1);//plain是解密后的二进制密文
            System.out.println(i + "轮迭代后：" + plain);
            System.out.println(i + "明文：" + BinaryTostringBuffer(plain));
            descipher.append(BinaryTostringBuffer(plain));
        }
        //输出解密后的明文
        System.out.println("最终解密后的明文："+descipher.substring(0,length));
    }

}
