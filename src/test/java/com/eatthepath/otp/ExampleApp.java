/* Copyright (c) 2016 Jon Chambers
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE. */

package com.eatthepath.otp;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.crypto.KeyGenerator;

import org.jboss.aerogear.security.otp.Totp;
import org.jboss.aerogear.security.otp.api.Base32;
import org.jboss.aerogear.security.otp.api.Clock;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;

import redis.clients.jedis.Jedis;

public class ExampleApp {
    public static void main(final String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();
        final HmacOneTimePasswordGenerator hotp = new HmacOneTimePasswordGenerator();

        final Key secretKey;
        {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());

            // SHA-1 and SHA-256 prefer 64-byte (512-bit) keys; SHA512 prefers 128-byte keys
            keyGenerator.init(512);

            secretKey = keyGenerator.generateKey();
        }

        final Date now = new Date();
        final Date later = new Date(now.getTime() + TimeUnit.SECONDS.toMillis(30));

        System.out.format("Current password: %06d\n", totp.generateOneTimePassword(secretKey, now));
        System.out.format("Future password:  %06d\n", totp.generateOneTimePassword(secretKey, later));
        System.out.format("hotp password:  %06d\n", hotp.generateOneTimePassword(secretKey, 8l));
        
        
        //生成客户端密钥的二维码
        /**
         * 主要的步骤如下：
			绑定密钥
			服务端为每个账户生成一个secret并保存下来
			服务端提供该密钥的二维码扫描功能，方便客户端扫描绑定账号
			用户手机安装Google Authenticator APP或阿里云的身份宝，扫描二维码绑定该账号的secret
		*/
        String secret = Base32.random();
        System.out.println(secret);
        Clock clock = new Clock(1);//验证码有些时间5min
        Totp generator = new Totp(secret,clock);
        String account = "13411111111";
        String uri = generator.uri(account);//账号
        System.out.println(uri);//将这个uri作为二维码的信息
        String filePath = "D:\\";
        String fileName = Long.toString(System.currentTimeMillis()) + ".png";
        try{
            generateMatrixPic(uri, 150, 150, filePath, fileName);
        }catch (Exception e){
            throw new RuntimeException("生成二维码图片失败:" + e.getMessage());
        }
        // the secret key (statically defined here but in practice it's obtained from the network)
        //String secret = "B2374TNIQ3HKC446";
        // initialize OTP
        //Totp generator = new Totp(secret);
        // generate token
        String resultOtp = generator.now();

        Jedis jedis = new Jedis("localhost");
        jedis.set("Token",resultOtp);
        
        
        System.out.println(resultOtp);
        
        boolean isValid = generator.verify(resultOtp);
        System.out.println(isValid);
        
        String token = jedis.get("Token");
        System.out.println("验证码>" + token);
    }
    
    public static void generateMatrixPic(String content, int height, int width, String filePath, String fileName) throws WriterException, IOException {
        Map<EncodeHintType, Object> hints = new HashMap<EncodeHintType, Object>();
        hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
        hints.put(EncodeHintType.MARGIN, 1);
        BitMatrix bitMatrix = new MultiFormatWriter().encode(content,
                BarcodeFormat.QR_CODE, width, height, hints);// 生成矩阵
        Path path = FileSystems.getDefault().getPath(filePath, fileName);
        MatrixToImageWriter.writeToPath(bitMatrix,"png",path);
    }
}
