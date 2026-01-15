package com.zyj.des.core;

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
    private StringBuffer plaintext;  // 明文字符串，每个明文块为64位二进制表示

    private StringBuffer secretKey;  // 密钥字符串，64位二进制表示

    private int groupCount;  // 分组数，表示明文需要分成多少个64位的块进行加密

    private DesStage desStage;  // DES算法的核心处理阶段对象，包含加密/解密的具体操作

    /**
     * 构造函数：从字符串创建DES加密对象
     *
     * @param plaintext 明文字符串（ASCII或文本）
     * @param secretKey 密钥字符串（8个字符，64位）
     */
    public DesCipher(String plaintext, String secretKey) {
        this(new StringBuffer(plaintext), new StringBuffer(secretKey));
    }

    /**
     * 构造函数：从StringBuffer创建DES加密对象
     *
     * @param plaintext 明文StringBuffer
     * @param secretKey 密钥StringBuffer
     */
    public DesCipher(StringBuffer plaintext, StringBuffer secretKey) {
        // 计算分组数：每个分组8个字符（64位），所以总字符数除以8
        this.groupCount = plaintext.length() / 8;
        // 对明文进行填充，确保长度是8的倍数（64位的整数倍）
        this.plaintext = expandTo64(plaintext);
        this.secretKey = secretKey;
        // 初始化DES处理阶段对象，传入密钥用于生成子密钥
        this.desStage = new DesStage(secretKey);
    }

    /**
     * 明文填充函数：将明文长度扩展到64位的整数倍
     * 使用PKCS#5风格的填充：填充的字节值等于需要填充的字节数
     * 例如：需要填充3个字节，则填充3个ASCII码为'3'的字符
     *
     * @param stringBuffer 原始明文字符串
     * @return 填充后的明文字符串
     */
    private StringBuffer expandTo64(StringBuffer stringBuffer) {
        // 计算需要填充的字节数（8 - 当前长度除以8的余数）
        int paddingByteNum = 8 - (stringBuffer.length() % 8);
        // 在末尾填充相应数量的填充字符
        for (int p = 0; p < paddingByteNum; p++) {
            stringBuffer.append(paddingByteNum);
        }
        return stringBuffer;
    }

    /**
     * DES算法的核心处理类，包含所有加密/解密的阶段和函数
     */
    public static final class DesStage {
        private final StringBuffer secretKey;  // 原始密钥（64位）

        /**
         * 构造函数：从字符串创建DesStage
         *
         * @param secretKey 密钥字符串
         */
        public DesStage(String secretKey) {
            this(new StringBuffer(secretKey));
        }

        /**
         * 构造函数：从StringBuffer创建DesStage
         *
         * @param secretKey 密钥StringBuffer
         */
        public DesStage(StringBuffer secretKey) {
            this.secretKey = secretKey;
        }

        /**
         * 初始置换（IP置换）：对64位输入块进行重新排列
         * 按照IP表（64个位置）重新排列输入位的顺序
         * 例如：原第58位移动到第1位，原第50位移动到第2位...
         *
         * @param r 64位输入块
         * @return 置换后的64位块
         */
        public StringBuffer initial(StringBuffer r) {
            StringBuffer res = new StringBuffer();
            // 遍历IP置换表的64个位置
            for (int i = 0; i < 64; i++) {
                // IP[i]-1：IP表中的值是1-based，需要转换为0-based索引
                res.append(r.charAt(IP[i] - 1));
            }
            return res;
        }

        /**
         * 16轮迭代函数：DES算法的核心迭代过程
         * 包含Feistel网络结构的16轮变换
         *
         * @param L    左32位输入
         * @param R    右32位输入
         * @param mode 模式：0-加密，1-解密
         * @return 经过16轮迭代后的64位结果
         */
        public StringBuffer iteration(StringBuffer L, StringBuffer R, int mode) {
            StringBuffer res = new StringBuffer();
            // 获取16个子密钥（用于16轮迭代）
            StringBuffer[] subkey = getSubkey();

            // mode == 1 表示解密模式，需要反转子密钥顺序
            // 加密：K1,K2,...,K16；解密：K16,K15,...,K1
            if (mode == 1) {
                StringBuffer[] tmp = getSubkey();  // 获取原始子密钥
                for (int i = 0; i < 16; i++) {
                    subkey[i] = tmp[15 - i];  // 反转密钥顺序
                }
            }

            // 16轮Feistel网络迭代
            for (int i = 0; i < 16; i++) {
                // 保存当前的L和R值，用于后续计算
                StringBuffer Ltmp = new StringBuffer(L);
                StringBuffer Rtmp = new StringBuffer(R);

                // Feistel结构的核心：右边的数据直接赋给左边
                // L[i] = R[i-1]
                L.replace(0, 32, R.toString());

                // F轮函数处理：对R[i-1]进行复杂的变换
                StringBuffer Fstring = F(Rtmp, subkey[i]);

                // R[i] = L[i-1] ⊕ F(R[i-1], K[i])
                // 异或操作：逐位比较，相同为0，不同为1
                for (int j = 0; j < 32; j++) {
                    R.replace(j, j + 1, (Fstring.charAt(j) == Ltmp.charAt(j) ? "0" : "1"));
                }
            }

            // 16轮迭代结束后，左右交换（Feistel结构的最后一步）
            StringBuffer RL = new StringBuffer(R + L.toString());

            // 终止置换（IP逆置换），得到最终输出
            RL = Final(RL);
            return RL;
        }

        /**
         * F轮函数：DES算法中最复杂的非线性变换部分
         * 包含：扩展、与子密钥异或、S盒替换、P置换
         *
         * @param R      32位输入数据
         * @param subkey 当前轮的子密钥（48位）
         * @return 32位输出数据
         */
        public StringBuffer F(StringBuffer R, StringBuffer subkey) {
            StringBuffer res;
            // 1. E盒扩展：将32位输入扩展到48位
            // 通过重复某些位实现扩展，使输入与48位子密钥长度匹配
            res = Extent(R);  // 32位 -> 48位

            // 2. 异或运算：扩展后的48位与子密钥逐位异或
            for (int i = 0; i < 48; i++) {
                res.replace(i, i + 1, (res.charAt(i) == subkey.charAt(i) ? "0" : "1"));
            }

            // 3. S盒压缩：48位 -> 32位，DES算法的非线性核心
            StringBuffer sBox = new StringBuffer();  // 存储S盒压缩后的32位结果

            // 8个S盒，每个处理6位输入，产生4位输出
            for (int i = 0; i < 8; i++) {
                // 获取当前S盒的6位输入
                String Sinput = res.substring(i * 6, (i + 1) * 6);

                // 计算S盒的行列索引：
                // - 行：6位输入的首位和末位组成2位二进制数（0-3）
                // - 列：6位输入的中间4位组成4位二进制数（0-15）
                int row = Integer.parseInt(Character.toString(Sinput.charAt(0)) + Sinput.charAt(5), 2);
                int column = Integer.parseInt(Sinput.substring(1, 5), 2);

                // 从S盒表中查找对应的4位输出值
                StringBuffer Soutput = new StringBuffer(Integer.toBinaryString(SBox[i][row * 16 + column]));

                // 确保输出为4位，不足4位在前面补0
                while (Soutput.length() < 4) {
                    Soutput.insert(0, 0);
                }
                sBox.append(Soutput);
            }

            // 4. P置换：对S盒输出的32位进行重新排列
            sBox = P(sBox);
            return sBox;
        }

        /**
         * P置换：对32位输入进行固定位置的重新排列
         * 按照P置换表（32个位置）重新排列位的顺序
         * 提供扩散性，使S盒的输出影响更多的位
         *
         * @param r 32位输入数据
         * @return 置换后的32位数据
         */
        public StringBuffer P(StringBuffer r) {
            StringBuffer res = new StringBuffer();
            for (int i = 0; i < 32; i++) {
                res.append(r.charAt(P[i] - 1));
            }
            return res;
        }

        /**
         * 扩展置换（E盒扩展）：将32位输入扩展到48位
         * 通过重复某些位的方式实现扩展：
         * - 将32位分成4位的块（共8块）
         * - 每块的左边添加前一块的最后一位，右边添加后一块的第一个位
         *
         * @param r 32位输入数据
         * @return 扩展后的48位数据
         */
        public StringBuffer Extent(StringBuffer r) {
            StringBuffer res = new StringBuffer();
            // 按照E扩展表的48个位置进行扩展
            for (int i = 0; i < 48; i++) {
                res.append(r.charAt(E[i] - 1));
            }
            return res;
        }

        /**
         * 终止置换（IP逆置换）：对16轮迭代后的结果进行最终置换
         * 这是初始置换IP的逆操作，使数据恢复到最后的状态
         * 按照IP逆置换表（64个位置）重新排列
         *
         * @param r 16轮迭代后的64位结果
         * @return 最终输出的64位密文/明文
         */
        public StringBuffer Final(StringBuffer r) {
            StringBuffer res = new StringBuffer();
            for (int i = 0; i < 64; i++) {
                res.append(r.charAt(IPReverse[i] - 1));
            }
            return res;
        }

        /**
         * 子密钥生成函数：从64位主密钥生成16个48位子密钥
         * 生成过程：PC1置换 -> 16轮循环移位 -> PC2置换
         *
         * @return 包含16个子密钥的数组
         */
        public StringBuffer[] getSubkey() {
            // 将密钥转换为二进制字符串
            StringBuffer keyBinary = new StringBuffer(stringBufferToBinary(secretKey));
            // 存储16个子密钥
            StringBuffer subkey[] = new StringBuffer[16];
            // C0和D0：PC1置换后得到的左右各28位
            StringBuffer C0 = new StringBuffer(); // 左28位
            StringBuffer D0 = new StringBuffer(); // 右28位

            // 确保密钥二进制长度为64位，不足时补0
            while (keyBinary.length() < 64) {
                keyBinary.append("0");
            }

            // PC1置换：64位 -> 56位（去除奇偶校验位）
            // 前28位放入C0，后28位放入D0
            for (int i = 0; i < 28; i++) {
                C0.append(keyBinary.charAt(PC1[i] - 1));
                D0.append(keyBinary.charAt(PC1[i + 28] - 1));
            }

            // 16轮循环，生成16个子密钥
            for (int i = 0; i < 16; i++) {
                // 左移操作：将第一位移动到末尾
                char tmp;
                tmp = C0.charAt(0);
                C0.deleteCharAt(0);
                C0.append(tmp);
                tmp = D0.charAt(0);
                D0.deleteCharAt(0);
                D0.append(tmp);

                // 特殊轮次（第1、2、9、16轮除外）需要左移两位
                if (i != 0 && i != 1 && i != 8 && i != 15) {
                    tmp = C0.charAt(0);
                    C0.deleteCharAt(0);
                    C0.append(tmp);
                    tmp = D0.charAt(0);
                    D0.deleteCharAt(0);
                    D0.append(tmp);
                }

                // 合并C和D部分：56位
                StringBuffer CODO = new StringBuffer(C0.toString() + D0.toString());

                // PC2置换：56位 -> 48位（选择48个特定位置）
                StringBuffer C0D0tmp = new StringBuffer();
                for (int j = 0; j < 48; j++) {
                    C0D0tmp.append(CODO.charAt(PC2[j] - 1));
                }
                subkey[i] = C0D0tmp;
            }
            return subkey;
        }
    }
}