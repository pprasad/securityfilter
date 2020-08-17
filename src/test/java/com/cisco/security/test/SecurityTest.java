package com.cisco.security.test;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.junit.Test;

import com.cisco.security.util.SecurityContants;

public class SecurityTest {

	private final Logger LOGGER=Logger.getLogger(SecurityTest.class);
	
	@Test
	public void sqlInjectionTest() throws UnsupportedEncodingException {
	   String queryString="selSubgroup=800FIXEDFEAT&selectedSubgroup=800FIXEDFEAT&ARCBANSAL=AIR-CT5508-100-K9&userId=&keyType=CREATEPAK&actionValue=&buttonPressed=Issue+PAK&featureOption=%5B%5D&featureQty=%5B%5D&locale=en_US&dispLicDatesFlag=false&dispProdQTYFlag=true&subGrpQTY=N&selectedSourceCAId=-1%3C%00script%09%3E217%2B%7BvalueOf%3Aalert%7D%3C%2Fscript%09%3E&selectedSourceCAName=&selectedSourceVAId=-1&selectedSourceVAName=&product_type=safenet&addressFlag=&cprWebData=&PRODUCTDESC=800-NR-TEST&features=C1-SL-1100-4P-APP&__multiselect_features=&noOfPaks=&hidden_pak_pref_val=MULTIPLE%3AN&Option0=C1-SL-1100-4P-APP+%3A+AppX+Foundation+License+for+Cisco+ISR+1100+4P+Series&qty0=1&Option1=&qty1=&Option2=&qty2=&Option3=&qty3=&Option4=&qty4=&ccoId=saiupadh&EMAIL=saiupadh%40cisco.com&SALESORDNO=SalesOrder&SUBSCRIPTIONID=&TACCASE=NA&NOTES=";
	   queryString=URLDecoder.decode(queryString,"UTF-8");
	   System.out.println(queryString);
	   boolean flag=isVulnerability(queryString);
	   
	   LOGGER.info("Request validate{}"+flag);
	   System.out.println("Request validate{}"+flag);
	}
	
	@Test
	public void contextTest() {
		String hostURL="http://cda-ui/software/cda/dist/images/ajax_loader.gif";
		String allowURL="cda-ui";
		Pattern p=Pattern.compile(allowURL);
		Matcher m=p.matcher(hostURL);
		System.out.println("HostURL{}"+hostURL.contains(allowURL));
	}
	
	@Test
	public void decoded() throws Exception {
		String msg="multipart/form-data;multipart/form-data; boundary=---------------------------11358752313534";
		msg=URLDecoder.decode(msg,"UTF-8");
		System.out.println(msg);
		boolean flag=isVulnerability(msg.trim());
		   
		   LOGGER.info("Request validate{}"+flag);
		   System.out.println("Request validate{}"+flag);
	}
	
	private boolean isVulnerability(String requestData) {
		return SecurityContants.isVulnerabilityCheckPoint(requestData);
	}
	
	@Test
	public void sqlInjectionTest1(){
		try{
		   String queryString="-----BEGIN CERTIFICATE REQUEST-----\r\nMIIChjCCAW4CAQAwQTEOMAwGA1UECgwFQ2lzY28xDTALBgNVBAsMBE5EQ1MxIDAe\r\nBgNVBAMMF3dlYmFwcHMtc3RhZ2UuY2lzY28uY29tMIIBIjANBgkqhkiG9w0BAQEF\r\nAAOCAQ8AMIIBCgKCAQEAx+U/ne5T5ci4G3ynwMMDjSC93/sLJyhQmcwQjhZCIpVP\r\nNJPEAXBPoQ658V1muzY5bYUDFC2kC0ih/b3r4B9fCRys2olXTQTOfdtVKp2oHPx/\r\nlqn2RqI2XKkA2GuluuIcMefSatpZQFDE68dQ//dNrLxlUI9inGAxXwGxzBTXpC+z\r\nblqPTUWCLjT61PoSQNdUhl4zK3tkJRPq0ZOvFxDcuFV8RlFrSxjhdp73CETTGWZc\r\nIARnYXPVEOQ5fO7UKoJaWNwFI/vAuntc9vZSa8fa0IZ3vzmvj/5P3Hdu7M1eAAbP\r\ngtYKDjtLz5v/F+b6zwD4bhKoqP3lIvi4+ubNglVfbQIDAQABoAAwDQYJKoZIhvcN\r\nAQEFBQADggEBACKhv1unYvUYNIaDz63qvyhqpU1QLrhdxDmHPk+D+5W3kMFIHGLj\r\nHykcuii9W2aVQDzzRe687OuNXnZjUULenTd7sDlNJgtFV8xytGKDlvff/53P9UN9\r\n+3K0BbtUIv+tS6nDJafnXd+kFXFjWPkfB2jBV/nq4MrO7LxeaeUxa4WR+Pek0fVY\r\nOJadaVaJzl+DOOtECWSaDvA2LD7MvMFlJBnoiwJD+Mqw61IeCcVR/2IvM+8xpHek\r\nYmUK9czx0diwuplZzN0X/3FOaQN80olQ9X+D7vVQBTju6b0ZlaodAsfh1I12lcHX\r\nQjLdhtthZbvt1EKv6z4xteZHmDnGaizbBl0=\r\n-----END CERTIFICATE REQUEST-----";
		   queryString=URLDecoder.decode(queryString,"UTF-8");
		   LOGGER.info(queryString);
		   boolean flag=isVulnerability(queryString);
		   
		   LOGGER.info("Request validate{}"+flag);
		}catch(Exception ex) {
		}
	}
	
	@Test
	public void sqlInjectionTest2(){
		try{
		   String queryString="useragent:demo';ddd";
		   queryString=URLDecoder.decode(queryString,"UTF-8");
		   LOGGER.info(queryString);
		   boolean flag=isVulnerability(queryString);
		   
		   LOGGER.info("Request validate{}"+flag);
		}catch(Exception ex) {
		}
	}
	
	@Test
	public void sqlInjectionTest3(){
		try{
		   String queryString="selectedMenuItemID=1&working_module=OS&fromPage=&module=ReleaseSelection&user_id=user50&release=+AIRAP&version_status=1&image_status=2&action_type=Select%2FView&family_t=&platform_t=&version_t=&release_t=&report_release_t=";
		   queryString=URLDecoder.decode(queryString,"UTF-8");
		   LOGGER.info(queryString);
		   boolean flag=isVulnerability(queryString);
		   
		   LOGGER.info("Request validate{}"+flag);
		}catch(Exception ex) {
		}
	}
	@Test
	public void pathTest() {
		String url="/demo/k";
		url=SecurityContants.getPath(url);
		LOGGER.info("URL:{}"+url);
		List<String> execludePaths=new ArrayList();
		LOGGER.info(execludePaths.contains(url));
	}
	
	@Test
	public void A1() {
		 int result;
		 result=2/5;
		 LOGGER.info("Result:{}"+result);
		 String envType="";
		 if(envType==null ||(envType!=null && envType.trim()==null)){
	    		envType="demo";
	     }
		 
	}
	@Test
	public void isValidRefererHeader() {
		String allowedReferers="swapi.cisco.com,software.cisco.com,localhost";
		String value=null;//"localhost:82";
		boolean flag=false;
		/*boolean flag=SecurityContants.isValidRefererHeader(value,allowedReferers);
		LOGGER.info("Valid Refereer:{}"+flag);*/
		value="http://localhost:82/software/cda/home";
		flag=SecurityContants.isValidRefererHeader(value,allowedReferers);
		LOGGER.info("Valid Refereer:{}"+flag);
	}
	
	@Test
	public void sqlInjectionTest4() {
		//String value="{\"product\":\"PAP2T/WRP400/SPA2xxx/SPA3xxx/SPA9xx/SPA3xx/SPA5xx\",\"duration\":\"180\",\"encryptionType\":\"SHA1\",\"csrContent\":\"-----BEGIN CERTIFICATE REQUEST-----\\r\\nMIICzjCCAbYCAQAwgYgxCzAJBgNVBAYTAkluMQswCQYDVQQIDAJBUDEQMA4GA1UE\\r\\nBwwHTmVsbG9yZTEQMA4GA1UECgwHemVuaW5mbzEQMA4GA1UECwwHWmVuaW5mbzEU\\r\\nMBIGA1UEAwwLWmVuaW5mb1RlY2gxIDAeBgkqhkiG9w0BCQEWEWFkbWluQHplbmlu\\r\\nZm90ZWNoMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuBISlrUsWpDg\\r\\nRkF5jx2VX9n16tasTMbLzex68ADvTMp5GfSrzFhXHqTniyAmtYvvEW3ZJERI/jB9\\r\\nJxija/HVz0xDfMQeQE3Knws+KiMRXRYYoW/O8Sk3ohQEQVVVmQrXp4fdCFvTwfVB\\r\\n7+0WBFIot1lDjhIoSwxKPfWwbHao6aQQdWJHRQQ16HGzAkPYHdg4VXz6rdKbqUY0\\r\\nbCHoDi5gGebJlvXL4teArmFabTSjWTshqTucjwWp3eDIGnTRi413mTxaWzlqZNqY\\r\\nqOR4zAU3KYsPOPyLjPVeBktB3dxMK87y9fetCFInmHTcn0lI4x5r6i1esM9JCAYM\\r\\nIGKrE7YALwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAI6PqFDCg95/iROJicCK\\r\\n6oAwm2AgVPfh7BGKim+7i+juczCZfFeydJu3N46xH4hecQQCrWbjil/Jq5sxaq7N\\r\\n6v292sREF4zOzHuFAz97XWDye7p3XG5ybr/02pyhogIuB64SQoEtaUoDeSwpr6rx\\r\\nymr/arLcUuJJFecJzQYwRRxk2T+0a84lpdAnL+pdSkXf5fwX4BFoDTJZJg+YuJCz\\r\\nMlEW1/Mm6irwBJdcKvjNKkzvIoqdSfsuq1vun9VfdveNOdghD81i96SwwJb25sVA\\r\\nZ+ciD12PE8KMsBvNLakGKHzUjW3Ot4QiA8aiVeCJArEBimkqCUJDbMbltYFr2UxL\\r\\n4jw=\\r\\n-----END CERTIFICATE REQUEST-----\",\"userId\":\"umprasad\"}";
		String value="/*+-?ppp*/";
		boolean flag=SecurityContants.isVulnerabilityCheckPoint(value);
		LOGGER.info("After scan flag:{}"+flag);
	}
}
