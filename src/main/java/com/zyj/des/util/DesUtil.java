package com.zyj.des.util;

import com.zyj.des.core.DesCipher;

import static com.zyj.des.util.BinaryUtil.BinaryTostringBuffer;
import static com.zyj.des.util.BinaryUtil.stringBufferToBinary;

public class DesUtil {
    public static String encrypt(String plaintext, String key) {
        return encrypt(new DesCipher(plaintext, key));
    }

    private static String encrypt(DesCipher desCipher) {
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
        // 分组解密
        // i的取值要根据分组长度区分
        int groupCount = plain.length() / 64 - 1;
        for (int i = 0; i <= groupCount; i++) {
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
            descipher.append(BinaryTostringBuffer(plain));
        }
        deleteMatchNumberAndSuffix(descipher);
        return descipher.toString();
    }

    /**
     * 删除【最右侧符合规则的连续数字段】及【该段之后的所有字符】
     * 匹配规则：存在 连续m个相同数字d ，满足 m = d(数字的字面量)
     * 处理示例1：xxx333alcib → 删除333+alcib → 结果xxx
     * 处理示例2：68656c6c6f20776f726c643388888888 ADUDD a → 删除88888888+空格+ADUDD+a → 结果68656c6c6f20776f726c6433
     */
    public static void deleteMatchNumberAndSuffix(StringBuffer sb) {
        // 空串/空对象 直接返回
        if (sb == null || sb.isEmpty()) {
            return;
        }

        // 从字符串尾部 向前遍历扫描，找符合规则的数字段
        for (int i = sb.length() - 1; i >= 0; i--) {
            char currChar = sb.charAt(i);
            // 遇到非数字，跳过继续向前找
            if (!Character.isDigit(currChar)) {
                continue;
            }
            // 拿到当前数字的字面量：就是需要连续出现的次数 m
            int matchCount = currChar - '0';
            // 数字是0 或 连续次数超过字符串长度，跳过
            if (matchCount <= 0 || matchCount > i + 1) {
                continue;
            }
            // 计算这个数字段的起始索引
            int startIndex = i - matchCount + 1;
            boolean isAllSame = true;
            // 校验：从startIndex到i的所有字符，是否都是当前这个数字
            for (int j = startIndex; j <= i; j++) {
                if (sb.charAt(j) != currChar) {
                    isAllSame = false;
                    break;
                }
            }
            // 匹配成功：删除【该数字段开始】到【字符串末尾】的所有内容，直接结束方法
            if (isAllSame) {
                sb.delete(startIndex, sb.length());
                return;
            }
        }
        // 遍历完没有匹配到符合规则的数字段，不做任何修改
    }
}
