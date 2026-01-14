package com.zyj.des;

import com.zyj.des.util.DesUtil;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static com.zyj.des.util.BinaryUtil.BinaryTostringBuffer;

@SpringBootTest
class DesImplApplicationTests {

	@Test
	void encrypt() {
		System.out.println(DesUtil.encrypt("hello world", "123456"));
	}
	@Test
	void contextLoads() {
		System.out.println(DesUtil.decrypt(
				"00101011011001011111101110101110011001011111110000010110010000111011001001100101101000101111101111000101001010111111000011000011",
				"123456"));
	}

}
