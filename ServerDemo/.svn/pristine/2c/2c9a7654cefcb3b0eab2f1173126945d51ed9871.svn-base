package cn.zifangsky.license;

import de.schlichtherle.license.LicenseContent;
import de.schlichtherle.license.LicenseContentException;
import de.schlichtherle.license.LicenseManager;
import de.schlichtherle.license.LicenseNotary;
import de.schlichtherle.license.LicenseParam;
import de.schlichtherle.license.NoLicenseInstalledException;
import de.schlichtherle.util.ObfuscatedString;
import de.schlichtherle.xml.GenericCertificate;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.beans.XMLDecoder;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.List;
import java.util.prefs.Preferences;

/**
 * 自定义LicenseManager，用于增加额外的服务器硬件信息校验
 *
 * @author zifangsky
 * @date 2018/4/23
 * @since 1.0.0
 */
public class CustomLicenseManager extends LicenseManager{
	
    private static Logger logger = LogManager.getLogger(CustomLicenseManager.class);
    /** => "exc.invalidSubject" */
    private static final String EXC_INVALID_SUBJECT = new ObfuscatedString(new long[] {
        0x8029CDF4E32A76ECL, 0x56FA623D9AEE8C1L, 0x99E7882A708663ACL,
        0x5888C0D72E548FF4L
    }).toString();

    /** => "exc.holderIsNull" */
    private static final String EXC_HOLDER_IS_NULL = new ObfuscatedString(new long[] {
        0x6339FEFCDFD84427L, 0x57A2FA0735E47CBEL, 0xED1D06E6EED72950L
    }).toString();

    /** => "exc.issuerIsNull" */
    private static final String EXC_ISSUER_IS_NULL = new ObfuscatedString(new long[] {
        0xD5E29AC879334756L, 0xF1F7421CD6A06536L, 0x5E086D6468FECBF2L
    }).toString();

    /** => "exc.issuedIsNull" */
    private static final String EXC_ISSUED_IS_NULL = new ObfuscatedString(new long[] {
        0xAB8FF89F2DA6C32CL, 0x2A089A9CA80D970EL, 0xCF15F8842FCCD9D5L
    }).toString();

    /** => "exc.licenseIsNotYetValid" */
    private static final String EXC_LICENSE_IS_NOT_YET_VALID = new ObfuscatedString(new long[] {
        0x4B6BB2804EE7DDB1L, 0xD0BB0A33A41543C5L, 0x5FCEC6DF3725CEE4L,
        0xA165775BBD625344L
    }).toString();
    

    /** => "exc.consumerTypeIsNull" */
    private static final String EXC_CONSUMER_TYPE_IS_NULL = new ObfuscatedString(new long[] {
        0xD29019F7B1D95C66L, 0xE859C44ACC3EB2FEL, 0xF041027C9003B031L,
        0x27E84AD8870D6063L
    }).toString();

    /** => "exc.consumerTypeIsNotUser" */
    private static final String EXC_CONSUMER_TYPE_IS_NOT_USER = new ObfuscatedString(new long[] {
        0xCE99D49CE98D1E47L, 0x7A3BA300A7DFCEABL, 0x2D2E4B624AD7C4E0L,
        0x2C86A28A075E71C6L, 0x79BCB920E5FB351DL
    }).toString();

    /** => "exc.consumerAmountIsNotOne" */
    private static final String EXC_CONSUMER_AMOUNT_IS_NOT_ONE = new ObfuscatedString(new long[] {
        0x5F20CBB98126BB0AL, 0xE8BB696B25D24011L, 0x435CC3AA7263BAE7L,
        0x9DA3066F501717E4L, 0x62FFA4899FBBA3F8L
    }).toString();

    /** => "exc.consumerAmountIsNotPositive" */
    private static final String EXC_CONSUMER_AMOUNT_IS_NOT_POSITIVE = new ObfuscatedString(new long[] {
        0xB14EB6259B4D7249L, 0xCD02F577511528D8L, 0x39B8CF1E258756DDL,
        0x67488F05891DF916L, 0x4256DE0CFFF62DCAL
    }).toString();

    /** => "fileFilter.description" */
    private static final String FILE_FILTER_DESCRIPTION = new ObfuscatedString(new long[] {
        0x2BDDE408C7B71604L, 0xDFCA7DA8912DE4C1L, 0xADA1FC1C1D5F1047L,
        0xD08EAA6CCDC342F3L
    }).toString();
    
    /** => "User" */
    private static final String USER = new ObfuscatedString(new long[] {
        0x9F89522C9F6F4A13L, 0xFFDB7A316241AC79L
    }).toString();


    //XML编码
    private static final String XML_CHARSET = "UTF-8";
    //默认BUFSIZE
    private static final int DEFAULT_BUFSIZE = 8 * 1024;

    public CustomLicenseManager() {

    }

    public CustomLicenseManager(LicenseParam param) {
        super(param);
    }

    /**
     * 复写create方法
     * @author zifangsky
     * @date 2018/4/23 10:36
     * @since 1.0.0
     * @param
     * @return byte[]
     */
    @Override
    protected synchronized byte[] create(
            LicenseContent content,
            LicenseNotary notary)
            throws Exception {
        initialize(content);
        this.validateCreate(content);
        final GenericCertificate certificate = notary.sign(content);
        return getPrivacyGuard().cert2key(certificate);
    }

    /**
     * 复写install方法，其中validate方法调用本类中的validate方法，校验IP地址、Mac地址等其他信息
     * @author zifangsky
     * @date 2018/4/23 10:40
     * @since 1.0.0
     * @param
     * @return de.schlichtherle.license.LicenseContent
     */
    @Override
    protected synchronized LicenseContent install(
            final byte[] key,
            final LicenseNotary notary)
            throws Exception {
        final GenericCertificate certificate = getPrivacyGuard().key2cert(key);

        notary.verify(certificate);
        final LicenseContent content = (LicenseContent)this.load(certificate.getEncoded());
        this.validate(content);
        setLicenseKey(key);
        setCertificate(certificate);

        return content;
    }

    /**
     * 复写verify方法，调用本类中的validate方法，校验IP地址、Mac地址等其他信息
     * @author zifangsky
     * @date 2018/4/23 10:40
     * @since 1.0.0
     * @param
     * @return de.schlichtherle.license.LicenseContent
     */
    @Override
    protected synchronized LicenseContent verify(final LicenseNotary notary)
            throws Exception {
        GenericCertificate certificate = getCertificate();

        // Load license key from preferences,
        final byte[] key = getLicenseKey();
        if (null == key){
            throw new NoLicenseInstalledException(getLicenseParam().getSubject());
        }

        certificate = getPrivacyGuard().key2cert(key);
        notary.verify(certificate);
        final LicenseContent content = (LicenseContent)this.load(certificate.getEncoded());
        this.validate(content);
        setCertificate(certificate);

        return content;
    }

    /**
     * 校验生成证书的参数信息
     * @author zifangsky
     * @date 2018/5/2 15:43
     * @since 1.0.0
     * @param content 证书正文
     */
    protected synchronized void validateCreate(final LicenseContent content)
            throws LicenseContentException {
        final LicenseParam param = getLicenseParam();
		/*
		 * final Date now = new Date(); final Date notBefore = content.getNotBefore();
		 * final Date notAfter = content.getNotAfter(); if (null != notAfter &&
		 * now.after(notAfter)){ throw new LicenseContentException("证书失效时间不能早于当前时间"); }
		 * if (null != notBefore && null != notAfter && notAfter.before(notBefore)){
		 * throw new LicenseContentException("证书生效时间不能晚于证书失效时间"); }
		 */
        final String consumerType = content.getConsumerType();
        if (null == consumerType){
            throw new LicenseContentException("用户类型不能为空");
        }
    }

    
    
    protected synchronized void Fvalidate(final LicenseContent content)
	    throws LicenseContentException {
	        final LicenseParam param = getLicenseParam();
	        if (!param.getSubject().equals(content.getSubject()))
	            throw new LicenseContentException(EXC_INVALID_SUBJECT);
	        if (null == content.getHolder())
	            throw new LicenseContentException(EXC_HOLDER_IS_NULL);
	        if (null == content.getIssuer())
	            throw new LicenseContentException(EXC_ISSUER_IS_NULL);
	        if (null == content.getIssued())
	            throw new LicenseContentException(EXC_ISSUED_IS_NULL);
	        final String consumerType = content.getConsumerType();
	        if (null == consumerType)
	            throw new LicenseContentException(EXC_CONSUMER_TYPE_IS_NULL);
	        final Preferences prefs = param.getPreferences();
	        if (null != prefs && prefs.isUserNode()) {
	            if (!USER.equalsIgnoreCase(consumerType))
	                throw new LicenseContentException(EXC_CONSUMER_TYPE_IS_NOT_USER);
	            if (1 != content.getConsumerAmount())
	                throw new LicenseContentException(EXC_CONSUMER_AMOUNT_IS_NOT_ONE);
	        } else {
	            if (0 >= content.getConsumerAmount())
	                throw new LicenseContentException(EXC_CONSUMER_AMOUNT_IS_NOT_POSITIVE);
	        }
	    }

    /**
     * 复写validate方法，增加IP地址、Mac地址等其他信息校验
     * @author zifangsky
     * @date 2018/4/23 10:40
     * @since 1.0.0
     * @param content LicenseContent
     */
    @Override
    protected synchronized void validate(final LicenseContent content)
            throws LicenseContentException {
        //1. 首先调用父类的validate方法
        this.Fvalidate(content);

        //2. 然后校验自定义的License参数
        //License中可被允许的参数信息
        LicenseCheckModel expectedCheckModel = (LicenseCheckModel) content.getExtra();
        //当前服务器真实的参数信息
        LicenseCheckModel serverCheckModel = getServerInfos();
        System.out.print(serverCheckModel.getDay());

        if(expectedCheckModel != null && serverCheckModel != null){
            //校验IP地址
            if(!checkIpAddress(expectedCheckModel.getIpAddress(),serverCheckModel.getIpAddress())){
                throw new LicenseContentException("当前服务器的IP没在授权范围内");
            }

            //校验Mac地址
            if(!checkIpAddress(expectedCheckModel.getMacAddress(),serverCheckModel.getMacAddress())){
                throw new LicenseContentException("当前服务器的Mac地址没在授权范围内");
            }

            //校验主板序列号
            if(!checkSerial(expectedCheckModel.getMainBoardSerial(),serverCheckModel.getMainBoardSerial())){
                throw new LicenseContentException("当前服务器的主板序列号没在授权范围内");
            }

            //校验CPU序列号
            if(!checkSerial(expectedCheckModel.getCpuSerial(),serverCheckModel.getCpuSerial())){
                throw new LicenseContentException("当前服务器的CPU序列号没在授权范围内");
            }
        }else{
            throw new LicenseContentException("不能获取服务器硬件信息");
        }
    }


    /**
     * 重写XMLDecoder解析XML
     * @author zifangsky
     * @date 2018/4/25 14:02
     * @since 1.0.0
     * @param encoded XML类型字符串
     * @return java.lang.Object
     */
    private Object load(String encoded){
        BufferedInputStream inputStream = null;
        XMLDecoder decoder = null;
        try {
            inputStream = new BufferedInputStream(new ByteArrayInputStream(encoded.getBytes(XML_CHARSET)));

            decoder = new XMLDecoder(new BufferedInputStream(inputStream, DEFAULT_BUFSIZE),null,null);

            return decoder.readObject();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } finally {
            try {
                if(decoder != null){
                    decoder.close();
                }
                if(inputStream != null){
                    inputStream.close();
                }
            } catch (Exception e) {
                logger.error("XMLDecoder解析XML失败",e);
            }
        }

        return null;
    }

    /**
     * 获取当前服务器需要额外校验的License参数
     * @author zifangsky
     * @date 2018/4/23 14:33
     * @since 1.0.0
     * @return demo.LicenseCheckModel
     */
    private LicenseCheckModel getServerInfos(){
        //操作系统类型
        String osName = System.getProperty("os.name").toLowerCase();
        AbstractServerInfos abstractServerInfos = null;

        //根据不同操作系统类型选择不同的数据获取方法
        if (osName.startsWith("windows")) {
            abstractServerInfos = new WindowsServerInfos();
        } else if (osName.startsWith("linux")) {
            abstractServerInfos = new LinuxServerInfos();
        }else{//其他服务器类型
            abstractServerInfos = new LinuxServerInfos();
        }

        return abstractServerInfos.getServerInfos();
    }

    /**
     * 校验当前服务器的IP/Mac地址是否在可被允许的IP范围内<br/>
     * 如果存在IP在可被允许的IP/Mac地址范围内，则返回true
     * @author zifangsky
     * @date 2018/4/24 11:44
     * @since 1.0.0
     * @return boolean
     */
    private boolean checkIpAddress(List<String> expectedList,List<String> serverList){
        if(expectedList != null && expectedList.size() > 0){
            if(serverList != null && serverList.size() > 0){
                for(String expected : expectedList){
                    if(serverList.contains(expected.trim())){
                        return true;
                    }
                }
            }

            return false;
        }else {
            return true;
        }
    }

    /**
     * 校验当前服务器硬件（主板、CPU等）序列号是否在可允许范围内
     * @author zifangsky
     * @date 2018/4/24 14:38
     * @since 1.0.0
     * @return boolean
     */
    private boolean checkSerial(String expectedSerial,String serverSerial){
        if(StringUtils.isNotBlank(expectedSerial)){
            if(StringUtils.isNotBlank(serverSerial)){
                if(expectedSerial.equals(serverSerial)){
                    return true;
                }
            }

            return false;
        }else{
            return true;
        }
    }

}
