package com.zyj.des.core;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.experimental.Accessors;

import static com.zyj.des.core.Constant.*;
import static com.zyj.des.core.Constant.E;
import static com.zyj.des.core.Constant.PC1;
import static com.zyj.des.core.Constant.PC2;
import static com.zyj.des.core.Constant.SBox;
import static com.zyj.des.util.BinaryUtil.stringBufferToBinary;

@Data
@Accessors(chain = true)
public class DesCipher {
    private StringBuffer plaintext;  //明文字符串64 bits----8 bytes

    private StringBuffer ciphertext;  //密文字符串64 bits----8 bytes

    private StringBuffer key;  //密钥字符串64 bits ----8 bytes

    private int group;  //分组

    private DesStage desStage;

    public DesCipher(StringBuffer plaintext, StringBuffer key){
        this.plaintext = plaintext;
        this.key = key;
        // 设置分组数
        this.group = plaintext.length() / 8;
        //初始化stage
        this.desStage = new DesStage(key);
    }

    @AllArgsConstructor
    public static final class DesStage {
        private StringBuffer key;

        //初始置换IP
        public StringBuffer initial(StringBuffer r) {
            StringBuffer res = new StringBuffer();
            for (int i = 0; i < 64; i++) {
                res.append(r.charAt(IP[i] - 1)); //数组的索引是从0开始的
            }
            return res;
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

        //终止置换IP
        public StringBuffer Final(StringBuffer r) {
            StringBuffer res = new StringBuffer();
            for (int i = 0; i < 64; i++) {
                res.append(r.charAt(IPReverse[i] - 1)); //数组的索引是从0开始的
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
    }
}
