package com.dspread.demoui.utils;






import org.bouncycastle.crypto.tls.TlsSRPGroupVerifier;

import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;

import javax.crypto.Cipher;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class DUKPK2009_CBC {


    public enum Enum_key {
        DATA, PIN, MAC, DATA_VARIANT;
    }

    public enum Enum_mode {
        ECB, CBC;
    }

    /*
    * ksnV:ksn
    * datastrV:data
    * Enum_key:Encryption/Decryption
    * Enum_mode
    *
    * */
    public static String getDate(String ksnV, String datastrV, Enum_key key, Enum_mode mode) {
        return getDate(ksnV, datastrV, key, mode, null);
    }

    public static String getDate(String ksnV, String datastrV, Enum_key key, Enum_mode mode, String clearIpek) {
        //		// TODO Auto-generated method stub
        String ksn = ksnV;
        String datastr = datastrV;
        byte[] ipek = null;
        byte[] byte_ksn = parseHexStr2Byte(ksn);
        if (clearIpek == null || clearIpek.length() == 0) {
            String bdk = "11111111111111111111111111111111";
            byte[] byte_bdk = parseHexStr2Byte(bdk);
            ipek = GenerateIPEK(byte_ksn, byte_bdk);

        } else {
            ipek = parseHexStr2Byte(clearIpek);
        }
        String ipekStr = parseByte2HexStr(ipek);// 经测试 ipek都一样
        System.out.println("ipekStr=" + ipekStr);
        byte[] dataKey = GetDataKey(byte_ksn, ipek);
        String dataKeyStr = parseByte2HexStr(dataKey);
        System.out.println("dataKeyStr=" + dataKeyStr);

        byte[] dataKeyVariant = GetDataKeyVariant(byte_ksn, ipek);
        String dataKeyStrVariant = parseByte2HexStr(dataKeyVariant);
        System.out.println("dataKeyStrVariant=" + dataKeyStrVariant);

        byte[] pinKey = GetPinKeyVariant(byte_ksn, ipek);
        String pinKeyStr = parseByte2HexStr(pinKey);
        System.out.println("pinKeyStr=" + pinKeyStr);

        byte[] macKey = GetMacKeyVariant(byte_ksn, ipek);
        String macKeyStr = parseByte2HexStr(macKey);
        System.out.println("macKeyStr=" + macKeyStr);

        String keySel = null;
        switch (key) {
            case MAC:
                keySel = macKeyStr;
                break;
            case PIN:
                keySel = pinKeyStr;
                break;
            case DATA:
                keySel = dataKeyStr;
                break;
            case DATA_VARIANT:
                keySel = dataKeyStrVariant;
                break;
        }

        byte[] buf = null;
        if (mode == Enum_mode.CBC)
            buf = TriDesDecryptionCBC(parseHexStr2Byte(keySel), parseHexStr2Byte(datastr));
        else if (mode == Enum_mode.ECB)
            buf = TriDesDecryptionECB(parseHexStr2Byte(keySel), parseHexStr2Byte(datastr));
        String deResultStr = parseByte2HexStr(buf);
//        System.out.println("data: " + deResultStr);
        return deResultStr;
    }


    public static byte[] GenerateIPEK(byte[] ksn, byte[] bdk) {
        byte[] result;
        byte[] temp, temp2, keyTemp;

        result = new byte[16];
        temp = new byte[8];
        keyTemp = new byte[16];

//        Array.Copy(bdk, keyTemp, 16);
        System.arraycopy(bdk, 0, keyTemp, 0, 16);   //Array.Copy(bdk, keyTemp, 16);
//        Array.Copy(ksn, temp, 8);
        System.arraycopy(ksn, 0, temp, 0, 8);    //Array.Copy(ksn, temp, 8);
        temp[7] &= 0xE0;
//        TDES_Enc(temp, keyTemp, out temp2);
        temp2 = TriDesEncryption(keyTemp, temp);    //TDES_Enc(temp, keyTemp, out temp2);temp
//        Array.Copy(temp2, result, 8);
        System.arraycopy(temp2, 0, result, 0, 8);   //Array.Copy(temp2, result, 8);
        keyTemp[0] ^= 0xC0;
        keyTemp[1] ^= 0xC0;
        keyTemp[2] ^= 0xC0;
        keyTemp[3] ^= 0xC0;
        keyTemp[8] ^= 0xC0;
        keyTemp[9] ^= 0xC0;
        keyTemp[10] ^= 0xC0;
        keyTemp[11] ^= 0xC0;
//        TDES_Enc(temp, keyTemp, out temp2);
        temp2 = TriDesEncryption(keyTemp, temp);    //TDES_Enc(temp, keyTemp, out temp2);
//        Array.Copy(temp2, 0, result, 8, 8);
        System.arraycopy(temp2, 0, result, 8, 8);   //Array.Copy(temp2, 0, result, 8, 8);
        return result;
    }


    public static byte[] GetDUKPTKey(byte[] ksn, byte[] ipek) {
//    	System.out.println("ksn===" + parseByte2HexStr(ksn));
        byte[] key;
        byte[] cnt;
        byte[] temp;
//    	byte shift;
        int shift;

        key = new byte[16];
//        Array.Copy(ipek, key, 16);
        System.arraycopy(ipek, 0, key, 0, 16);

        temp = new byte[8];
        cnt = new byte[3];
        cnt[0] = (byte) (ksn[7] & 0x1F);
        cnt[1] = ksn[8];
        cnt[2] = ksn[9];
//        Array.Copy(ksn, 2, temp, 0, 6);
        System.arraycopy(ksn, 2, temp, 0, 6);
        temp[5] &= 0xE0;

        shift = 0x10;
        while (shift > 0) {
            if ((cnt[0] & shift) > 0) {
//            	System.out.println("**********");
                temp[5] |= shift;
                NRKGP(key, temp);
            }
            shift >>= 1;
        }
        shift = 0x80;
        while (shift > 0) {
            if ((cnt[1] & shift) > 0) {
//            	System.out.println("&&&&&&&&&&");
                temp[6] |= shift;
                NRKGP(key, temp);
            }
            shift >>= 1;
        }
        shift = 0x80;
        while (shift > 0) {
            if ((cnt[2] & shift) > 0) {
//            	System.out.println("^^^^^^^^^^");
                temp[7] |= shift;
                NRKGP(key, temp);
            }
            shift >>= 1;
        }

        return key;
    }

    /// <summary>
    /// Non Reversible Key Generatino Procedure
    /// private function used by GetDUKPTKey
    /// </summary>
    private static void NRKGP(byte[] key, byte[] ksn) {

        byte[] temp, key_l, key_r, key_temp;
        int i;

        temp = new byte[8];
        key_l = new byte[8];
        key_r = new byte[8];
        key_temp = new byte[8];

//        Console.Write("");

//        Array.Copy(key, key_temp, 8);
        System.arraycopy(key, 0, key_temp, 0, 8);
        for (i = 0; i < 8; i++)
            temp[i] = (byte) (ksn[i] ^ key[8 + i]);
//        DES_Enc(temp, key_temp, out key_r);
        key_r = TriDesEncryption(key_temp, temp);
        for (i = 0; i < 8; i++)
            key_r[i] ^= key[8 + i];

        key_temp[0] ^= 0xC0;
        key_temp[1] ^= 0xC0;
        key_temp[2] ^= 0xC0;
        key_temp[3] ^= 0xC0;
        key[8] ^= 0xC0;
        key[9] ^= 0xC0;
        key[10] ^= 0xC0;
        key[11] ^= 0xC0;

        for (i = 0; i < 8; i++)
            temp[i] = (byte) (ksn[i] ^ key[8 + i]);
//        DES_Enc(temp, key_temp, out key_l);
        key_l = TriDesEncryption(key_temp, temp);
        for (i = 0; i < 8; i++)
            key[i] = (byte) (key_l[i] ^ key[8 + i]);
//        Array.Copy(key_r, 0, key, 8, 8);
        System.arraycopy(key_r, 0, key, 8, 8);
    }

    /// <summary>
    /// Get current Data Key variant
    /// Data Key variant is XOR DUKPT Key with 0000 0000 00FF 0000 0000 0000 00FF 0000
    /// </summary>
    /// <param name="ksn">Key serial number(KSN). A 10 bytes data. Which use to determine which BDK will be used and calculate IPEK. With different KSN, the DUKPT system will ensure different IPEK will be generated.
    /// Normally, the first 4 digit of KSN is used to determine which BDK is used. The last 21 bit is a counter which indicate the current key.</param>
    /// <param name="ipek">IPEK (16 byte).</param>
    /// <returns>Data Key variant (16 byte)</returns>
    public static byte[] GetDataKeyVariant(byte[] ksn, byte[] ipek) {
        byte[] key;

        key = GetDUKPTKey(ksn, ipek);
        key[5] ^= 0xFF;
        key[13] ^= 0xFF;

        return key;
    }

    /// <summary>
    /// Get current PIN Key variant
    /// PIN Key variant is XOR DUKPT Key with 0000 0000 0000 00FF 0000 0000 0000 00FF
    /// </summary>
    /// <param name="ksn">Key serial number(KSN). A 10 bytes data. Which use to determine which BDK will be used and calculate IPEK. With different KSN, the DUKPT system will ensure different IPEK will be generated.
    /// Normally, the first 4 digit of KSN is used to determine which BDK is used. The last 21 bit is a counter which indicate the current key.</param>
    /// <param name="ipek">IPEK (16 byte).</param>
    /// <returns>PIN Key variant (16 byte)</returns>
    public static byte[] GetPinKeyVariant(byte[] ksn, byte[] ipek) {
        byte[] key;

        key = GetDUKPTKey(ksn, ipek);
        key[7] ^= 0xFF;
        key[15] ^= 0xFF;

        return key;
    }

    public static byte[] GetMacKeyVariant(byte[] ksn, byte[] ipek) {
        byte[] key;

        key = GetDUKPTKey(ksn, ipek);
        key[6] ^= 0xFF;
        key[14] ^= 0xFF;

        return key;
    }

    public static byte[] GetDataKey(byte[] ksn, byte[] ipek) {
        byte[] temp1 = GetDataKeyVariant(ksn, ipek);
        byte[] temp2 = temp1;

        byte[] key = TriDesEncryption(temp2, temp1);

        return key;
    }

    // 3DES加密
    public static byte[] TriDesEncryption(byte[] byteKey, byte[] dec) {

        try {
            byte[] en_key = new byte[24];
            if (byteKey.length == 16) {
                System.arraycopy(byteKey, 0, en_key, 0, 16);
                System.arraycopy(byteKey, 0, en_key, 16, 8);
            } else if (byteKey.length == 8) {
                System.arraycopy(byteKey, 0, en_key, 0, 8);
                System.arraycopy(byteKey, 0, en_key, 8, 8);
                System.arraycopy(byteKey, 0, en_key, 16, 8);
            } else {
                en_key = byteKey;
            }
            SecretKeySpec key = new SecretKeySpec(en_key, "DESede");

            Cipher ecipher = Cipher.getInstance("DESede/ECB/NoPadding");
            ecipher.init(Cipher.ENCRYPT_MODE, key);

            // Encrypt
            byte[] en_b = ecipher.doFinal(dec);

            // String en_txt = parseByte2HexStr(en_b);
            // String en_txt =byte2hex(en_b);
            return en_b;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // 3DES解密 CBC
    public static byte[] TriDesDecryptionCBC(byte[] byteKey, byte[] dec) {
        byte[] en_key = new byte[24];
        if (byteKey.length == 16) {
            System.arraycopy(byteKey, 0, en_key, 0, 16);
            System.arraycopy(byteKey, 0, en_key, 16, 8);
        } else if (byteKey.length == 8) {
            System.arraycopy(byteKey, 0, en_key, 0, 8);
            System.arraycopy(byteKey, 0, en_key, 8, 8);
            System.arraycopy(byteKey, 0, en_key, 16, 8);
        } else {
            en_key = byteKey;
        }

        try {
            Key deskey = null;
            byte[] keyiv = new byte[8];
            DESedeKeySpec spec = new DESedeKeySpec(en_key);
            SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("desede");
            deskey = keyfactory.generateSecret(spec);

            Cipher cipher = Cipher.getInstance("desede" + "/CBC/NoPadding");
            IvParameterSpec ips = new IvParameterSpec(keyiv);

            cipher.init(Cipher.DECRYPT_MODE, deskey, ips);

            byte[] de_b = cipher.doFinal(dec);

            return de_b;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    // 3DES解密 ECB
    public static byte[] TriDesDecryptionECB(byte[] byteKey, byte[] dec) {
        // private String TriDesDecryption(String dnc_key, byte[] dec){
        // byte[] byteKey = parseHexStr2Byte(dnc_key);
        byte[] en_key = new byte[24];
        if (byteKey.length == 16) {
            System.arraycopy(byteKey, 0, en_key, 0, 16);
            System.arraycopy(byteKey, 0, en_key, 16, 8);
        } else if (byteKey.length == 8) {
            System.arraycopy(byteKey, 0, en_key, 0, 8);
            System.arraycopy(byteKey, 0, en_key, 8, 8);
            System.arraycopy(byteKey, 0, en_key, 16, 8);
        } else {
            en_key = byteKey;
        }
        SecretKey key = null;

        try {
            key = new SecretKeySpec(en_key, "DESede");
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        try {
            Cipher dcipher = Cipher.getInstance("DESede/ECB/NoPadding");
            dcipher.init(Cipher.DECRYPT_MODE, key);

            // byte[] dec = parseHexStr2Byte(en_data);

            // Decrypt
            byte[] de_b = dcipher.doFinal(dec);

            // String de_txt = parseByte2HexStr(removePadding(de_b));
            return de_b;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // 十六进制字符串转字节数组
    public static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1)
            return null;
        byte[] result = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2),
                    16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }

    // 字节数组转十六进制字符串
    public static String parseByte2HexStr(byte buf[]) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }

    // 数据补位
    public static String dataFill(String dataStr) {
        int len = dataStr.length();
        if (len % 16 != 0) {
            dataStr += "80";
            len = dataStr.length();
        }
        while (len % 16 != 0) {
            dataStr += "0";
            len++;
            System.out.println(dataStr);
        }
        return dataStr;
    }


    public static String xor(String key1, String key2) {
        String result = "";

        byte[] arr1 = parseHexStr2Byte(key1);
        byte[] arr2 = parseHexStr2Byte(key2);
        byte[] arr3 = new byte[arr1.length];

        for (int i = 0; i < arr1.length; i++) {
            arr3[i] = (byte) (arr1[i] ^ arr2[i]);
        }

        result = parseByte2HexStr(arr3);
        return result;
    }




    public static void main(String[] args) throws InterruptedException {
//        07-08 17:50:27.306 12376-12376/com.dspread.demoui D/POS_SDK: onRequestOnlineProcess5F201A20202020202020202020202020202020202020202020202020204F08A0000003330101015F24032612319F160F4243544553542031323334353637389F21031750229A031907089F02060000000001119F03060000000000009F34030203009F120A50424F432044454249549F0607A00000033301015F300202209F4E0F616263640000000000000000000000C408622622FFFFFF3603C10A09118012400705E00002C708DBD7F58811779698C00A09118012400705E00001C28201880C54D377643A72400707E993BDEB6AFD891CFD5EC8CA03A251DF9301E70F76999ADABCECF859C26B9320724644D15B53BDE669414C7C8336EFDC0892A6F883DB5163D0613557949D66349BB6CB6BBCD8877017D3FEF5404C4446F2F2244CB62C62CAAE6EB86F99C9F31E69DB32BBDA2390A73EA907E4D8BDEED105E876319F4D17A5DE1788B0DA32730E4102F42A7232BE4D9D5E7BF46E7313C0F190E4F7A7D320D29DD3765E06DB5FE847C8B2B5ABBBAC0B22E5C9722303EF6E1C050C33B4F88D1BE8E79A8FBACA1086E466CB79A54A528DF53D98DA85E79EACAC4F464B0BC2941A540E1E6DFA47D4D369F50BEECFDC37AED04F63500BED4D4DB524E69345F6FE94A1CB2353D39959953393ADDD7930A43E2FCC3AE8AB348B0A8025C63C8650AF6F7C2F613EEF31549B6E073898D256815A851B5C39341B609BB3DB9974985550F096DEA5440B429BB0346D93FC25A17441F27F219A4004EE2A244014434E5D17B9F645CACB534E0CF7D3D555EE861780CF33A674D0A9A04C523C85D3F8062CE34309514A32F2AA

//        String tlvDate = "5F201A20202020202020202020202020202020202020202020202020204F08A0000003330101015F24032612319F160F4243544553542031323334353637389F21031750229A031907089F02060000000001119F03060000000000009F34030203009F120A50424F432044454249549F0607A00000033301015F300202209F4E0F616263640000000000000000000000C408622622FFFFFF3603C10A09118012400705E00002C708DBD7F58811779698C00A09118012400705E00001C28201880C54D377643A72400707E993BDEB6AFD891CFD5EC8CA03A251DF9301E70F76999ADABCECF859C26B9320724644D15B53BDE669414C7C8336EFDC0892A6F883DB5163D0613557949D66349BB6CB6BBCD8877017D3FEF5404C4446F2F2244CB62C62CAAE6EB86F99C9F31E69DB32BBDA2390A73EA907E4D8BDEED105E876319F4D17A5DE1788B0DA32730E4102F42A7232BE4D9D5E7BF46E7313C0F190E4F7A7D320D29DD3765E06DB5FE847C8B2B5ABBBAC0B22E5C9722303EF6E1C050C33B4F88D1BE8E79A8FBACA1086E466CB79A54A528DF53D98DA85E79EACAC4F464B0BC2941A540E1E6DFA47D4D369F50BEECFDC37AED04F63500BED4D4DB524E69345F6FE94A1CB2353D39959953393ADDD7930A43E2FCC3AE8AB348B0A8025C63C8650AF6F7C2F613EEF31549B6E073898D256815A851B5C39341B609BB3DB9974985550F096DEA5440B429BB0346D93FC25A17441F27F219A4004EE2A244014434E5D17B9F645CACB534E0CF7D3D555EE861780CF33A674D0A9A04C523C85D3F8062CE34309514A32F2AA";
//        List<TLV> parse = TLVParser.parse(tlvDate);
//        //c0
//        String onLineksn = TLVParser.searchTLV(parse, "c0").value;
//        //c2
//		String onLineblockData = TLVParser.searchTLV(parse, "c2").value;
//        //c1
//        String Pinksn = TLVParser.searchTLV(parse, "c1").value;
//        //c7
//        String pinblockData = TLVParser.searchTLV(parse, "c7").value;
//        String pin = getDate(Pinksn, pinblockData, Enum_key.PIN, Enum_mode.ECB);
//
		String onLinedate = getDate("00219090600483E00002", "76DF3C232F9D1E89C5C4D3EF291401173261F356947E7B036D8EA42E240CB4C98512E9673563C98F324F7793E98897EA5B531247190DEB71EC17348D3A95F90022595EC51948117AB216DF364C1C2E236CE0E98F7587D9751530FB576B774A8F5C162A070530A645FB944D605C71EC15AB9689BE00B29A8E03A99042656B18B7AD8E0748A21785A3405989A0145D6D0721258882D074881A6D5F6E0E2A58BC4CE1F52F2F1EF1A06B6ADB515A592577621288131E41DF83B020C88C771D90E6F44D169C492B8DA1987DA3421EC36FB616B454A669800DD796F7CF51A110D1D774E4A5023A664C7DEEB28880E74D644D146E70FEC68BE9E85E4FFA3060E38EB2700A634777988728E16896D496828CD67461CE629347436829142060732B140BA7C27F837783A032D8286D3025B3A92E5B84D6DF0EDA8BC696B647013AAAC7627812A46AE7AF3470003CF775C95FE55CDC83EC1FD65795F375FFFCEF3C3B349B3D22B5982EAC191CDE2F49A5E098386E13AFC5A9CBBB384B538A16B09C9FDAD5B2EBD963B1AE7927C6", Enum_key.DATA, Enum_mode.CBC);
        System.out.print(onLinedate);
//        parse = TLVParser.parse(onLinedate);
//		String realPan = TLVParser.searchTLV(parse, "5A").value;
//		String parsCarN = "0000" + realPan.substring(realPan.length() - 13, realPan.length() - 1);
//		String realPin = xor(parsCarN, pin);
//        System.out.print(realPin);

//        String TRksn = "FFFF9876543210E00004";
//        String TrackblockData = "C16053106DB25F18DF77ABAB29F4D65B2EA461C95C46F00AF5A5E65E5EC1C31DCB4C557C47862FA4E640F5DE8BE49B48DCA7C14271D07EE952643A44482CC5029B65933F26298181D45F3F9CA3986DD551F2D97BBBFDD46FD1A90C3CD18BB6E40A67F9BDA19722FB722A06B05A19FEBD27A4BCA4D4B1A882EF4533723E0F5C778521A7683E98F33F6382960EB9C8C7AE2A69C524E3992A2E056E2DBC3C80B19F84605CED36AC5F7004C50FEEF49B199298ADE2299AE681C3B5BEE3169C7AA6A1811214586565DCD8AEB938B50ECCEE24C9E2D9BE4BD0B1F30383B9FAF5B96079A8CBCC03B66DAD92D7A85F58763931B56B3399AC76DB17BA73886A5425E2C8694CD0ADD9C461986D7C2B64FDAC75F2E2F3158FF93D991E0BFF299E76B052DCAB9F0A9EED7561034A12850100484F6FC1C0DEA471B39F2E117855407E642940574F8A985498624BFD602589A86044E9FD922616778B74165A6E452C518C49E3E807C758EF3FCA8483ADA9085249C54D3ACF7BA5EBD5B14C685802C76E934807BA1E67F2F4A043DFC46328F50C3103920A";

//     解密后数据   7082019E9F02060000000167659F160F4243544553543132333435363738005F24032212314F07A00000000410109F34034103029A031905299F03060000000000009F0607A00000000410109F21032331129F120A4D6173746572436172645A08222360008902032957132223600089020329D22122010123409172029F9F10120110A50009020000000000000000000000FF9F4E0F616263640000000000000000000000820239008E1200000000000000004201440341035E031F035F25031604019F0702FF009F0D05BC50BC80009F0E0500000000009F0F05BC70BC98009F26085987C9E1521501C19F2701809F3602052F9C01009F3303E0F8C89F3704155DA29D9F3901059F4005F000F0A001950504800080009B02E8008407A00000000410105F2A0201565F3401019F090200969F1A0208409F1E0838333230314943439F3501229F4104000018699F5301525F201A554154205553412F5465737420436172642032312020202020205F300202015F28020840500A4D4153544552434152449F080200029F01060012345678909F150212349F1C084E4C2D4750373330000000000000


    }






}
