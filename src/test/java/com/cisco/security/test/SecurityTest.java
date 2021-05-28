package com.cisco.security.test;
import static com.cisco.security.util.SecurityContants.setAllowedHeadersRegex;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.junit.BeforeClass;
import org.junit.Test;

import com.cisco.security.util.SecurityContants;

public class SecurityTest {

	private final Logger LOGGER=LoggerFactory.getLogger(SecurityTest.class);
	
	
	@Test
	public void sqlInjectionTest() throws UnsupportedEncodingException {
	   //String queryString="selSubgroup=800FIXEDFEAT&selectedSubgroup=800FIXEDFEAT&ARCBANSAL=AIR-CT5508-100-K9&userId=&keyType=CREATEPAK&actionValue=&buttonPressed=Issue+PAK&featureOption=%5B%5D&featureQty=%5B%5D&locale=en_US&dispLicDatesFlag=false&dispProdQTYFlag=true&subGrpQTY=N&selectedSourceCAId=-1%3C%00script%09%3E217%2B%7BvalueOf%3Aalert%7D%3C%2Fscript%09%3E&selectedSourceCAName=&selectedSourceVAId=-1&selectedSourceVAName=&product_type=safenet&addressFlag=&cprWebData=&PRODUCTDESC=800-NR-TEST&features=C1-SL-1100-4P-APP&__multiselect_features=&noOfPaks=&hidden_pak_pref_val=MULTIPLE%3AN&Option0=C1-SL-1100-4P-APP+%3A+AppX+Foundation+License+for+Cisco+ISR+1100+4P+Series&qty0=1&Option1=&qty1=&Option2=&qty2=&Option3=&qty3=&Option4=&qty4=&ccoId=saiupadh&EMAIL=saiupadh%40cisco.com&SALESORDNO=SalesOrder&SUBSCRIPTIONID=&TACCASE=NA&NOTES=";
	   //queryString=URLDecoder.decode(queryString,"UTF-8");
	String queryString="!@#$%^&*()-_+={}[]:;'\\\"\\\\,./<>?|`\\n\\r\\t";   
	System.out.println(queryString);
	   //String payload="{    \"flag\": \"N\",    \"userID\": \"ahumne\",     \"paginationALreadySet\": true,    \"srcCaId\": 0,    \"contextSA\":    {        \"companyAccId\": \"0\",        \"sourceCaId\": \"0\",        \"sourceCaName\": \"\",        \"virtualAccountList\":        [            {                \"virtualAccountId\": \"0\",                \"virtualAccountName\": null,                \"defaultFlag\": false,                \"displayFlag\": false,                \"selectedFlag\": \"Y\"            }        ],        \"displayCaName\": null,        \"displayCaMsg\": null,        \"isSmartAdmin\": false,        \"domainIdentifier\": null,        \"accountType\": null,        \"smartAdmin\": false    },    \"paginationForm\":    {        \"noOfPages\": 0,        \"pageNo\": 1,        \"pageNoEndIndex\": 0,        \"pageNoStartIndex\": 0,        \"perPage\": 10,        \"recordEndIndex\": 0,        \"recordStartIndex\": 0,        \"totalListSize\": 0    },    \"pakTabFilter\":    {        \"ciscoSO\": \"\",        \"companyAccount\": \"\",        \"lineID\": \"\",        \"orderLineId\": \"\",        \"orderNumber\": \"\",        \"pakId\": \"\",        \"productFamily\": \"\",        \"qty\": \"\",        \"sku\": \"\",        \"skuDesc\": \"\",        \"sortColumn\": \"\",        \"sortOrder\": \"\",        \"status\": \"\",        \"subGroup\": \"\",        \"subscriptionId\": \"\",        \"usedQTY\": \"\"    }}";
	   boolean flag=isVulnerability(queryString);
	   System.out.println("Status:{}"+flag);
	   LOGGER.info("Request validate{}"+flag);
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
		LOGGER.info("Context URL"+execludePaths.contains(url));
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
	
	@Test
	public void emailTest() {
		String regex="^(.+)@(.+)$";
		String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\."+
				"[a-zA-Z0-9_+&*-]+)*@" +
				"(?:[a-zA-Z0-9-]+\\.)+[a-z" +
				"A-Z]{2,7}$";
		Pattern p=Pattern.compile(emailRegex,Pattern.CASE_INSENSITIVE);
		System.out.println("Email:{}"+p.matcher("umprasad@cisco.com").find());
	}
	
	@Test
	public void testPayload() {
		String payload="{\r\n" + 
				"	\"requestType\": \"TEST\",\r\n" + 
				"	\"refId\": \"1785f025d0dWO3a2002333831353437313933\",\r\n" + 
				"	\"businessScenario\": 0,\r\n" + 
				"	\"transactionType\": \"CCW-CO\",\r\n" + 
				"	\"sbpOrderLineId\": \"\",\r\n" + 
				"	\"hasValidation\": \"Y\",\r\n" + 
				"	\"hasMandatoryFields\": \"N\",\r\n" + 
				"	\"provisionAttributes\": [\r\n" + 
				"		{\r\n" + 
				"			\"groupId\": 11,\r\n" + 
				"			\"groupName\": \"Customer Info\",\r\n" + 
				"			\"groupCode\": \"Customer Info\",\r\n" + 
				"			\"type\": null,\r\n" + 
				"			\"prvId\": 23738,\r\n" + 
				"			\"webOrderId\": \"381547193\",\r\n" + 
				"			\"transactionId\": 3809281,\r\n" + 
				"			\"userId\": \"yhargrove\",\r\n" + 
				"			\"majorLineTransactionId\": 3809282,\r\n" + 
				"			\"attributeDetails\": [\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 534752,\r\n" + 
				"					\"itemName\": \"Lckhrt\",\r\n" + 
				"					\"attributeName\": \"Lckhrt End Customer Contact Name\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 1,\r\n" + 
				"					\"maxLength\": 60,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 1,\r\n" + 
				"					\"questionId\": 63,\r\n" + 
				"					\"tfsUIDesc\": \"End Customer Contact Name\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP000049\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000047\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"02/20/2020\",\r\n" + 
				"					\"puiEntryOn\": \"02/20/2020\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 534753,\r\n" + 
				"					\"itemName\": \"Lckhrt\",\r\n" + 
				"					\"attributeName\": \"Lckhrt End Customer Contact Email\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 1,\r\n" + 
				"					\"maxLength\": 60,\r\n" + 
				"					\"dataType\": \"Email\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 2,\r\n" + 
				"					\"questionId\": 64,\r\n" + 
				"					\"tfsUIDesc\": \"End Customer Contact Email\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP000048\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000047\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"02/20/2020\",\r\n" + 
				"					\"puiEntryOn\": \"02/20/2020\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 534754,\r\n" + 
				"					\"itemName\": \"Lckhrt\",\r\n" + 
				"					\"attributeName\": \"Lckhrt End Customer Administrator Name\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 1,\r\n" + 
				"					\"maxLength\": 60,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 3,\r\n" + 
				"					\"questionId\": 65,\r\n" + 
				"					\"tfsUIDesc\": \"End Customer Administrator Name\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP000071\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000047\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"02/20/2020\",\r\n" + 
				"					\"puiEntryOn\": \"02/20/2020\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 534755,\r\n" + 
				"					\"itemName\": \"Lckhrt\",\r\n" + 
				"					\"attributeName\": \"Lckhrt End Customer Administrator Email\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 1,\r\n" + 
				"					\"maxLength\": 60,\r\n" + 
				"					\"dataType\": \"Email\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 4,\r\n" + 
				"					\"questionId\": 66,\r\n" + 
				"					\"tfsUIDesc\": \"End Customer Administrator Email\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP000070\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000047\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"02/20/2020\",\r\n" + 
				"					\"puiEntryOn\": \"02/20/2020\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 534756,\r\n" + 
				"					\"itemName\": \"Lckhrt\",\r\n" + 
				"					\"attributeName\": \"Lckhrt End Customer Company Name\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 1,\r\n" + 
				"					\"maxLength\": 60,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 5,\r\n" + 
				"					\"questionId\": 62,\r\n" + 
				"					\"tfsUIDesc\": \"End Customer Company Name\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP000072\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000047\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"02/20/2020\",\r\n" + 
				"					\"puiEntryOn\": \"02/20/2020\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				}\r\n" + 
				"			]\r\n" + 
				"		},\r\n" + 
				"		{\r\n" + 
				"			\"groupId\": 13,\r\n" + 
				"			\"groupName\": \"Site Information\",\r\n" + 
				"			\"groupCode\": \"Additional Site Information\",\r\n" + 
				"			\"type\": null,\r\n" + 
				"			\"prvId\": 23738,\r\n" + 
				"			\"webOrderId\": \"381547193\",\r\n" + 
				"			\"transactionId\": 3809281,\r\n" + 
				"			\"userId\": \"yhargrove\",\r\n" + 
				"			\"majorLineTransactionId\": 3809282,\r\n" + 
				"			\"attributeDetails\": [\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339272,\r\n" + 
				"					\"itemName\": \"Webex Core\",\r\n" + 
				"					\"attributeName\": \"SERVICE URL\",\r\n" + 
				"					\"attributeValue\": \"zensar.webex.com\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 1,\r\n" + 
				"					\"maxLength\": 60,\r\n" + 
				"					\"dataType\": \"URL\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 20,\r\n" + 
				"					\"questionId\": 84,\r\n" + 
				"					\"tfsUIDesc\": \"Site URL (companyname.webex.com)\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP000013\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000026\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Site\",\r\n" + 
				"					\"prvGroupId\": 1,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": \"UPDATED\"\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339273,\r\n" + 
				"					\"itemName\": \"Webex Brand\",\r\n" + 
				"					\"attributeName\": \"BRANDING REF\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 60,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Horizontal\",\r\n" + 
				"					\"displayOrder\": 21,\r\n" + 
				"					\"questionId\": 88,\r\n" + 
				"					\"tfsUIDesc\": \"Branding Reference URL (eg. www.companyname.com)\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"N\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000026\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Site\",\r\n" + 
				"					\"prvGroupId\": 1,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339274,\r\n" + 
				"					\"itemName\": \"Webex Core\",\r\n" + 
				"					\"attributeName\": \"COUNTRY CODE\",\r\n" + 
				"					\"attributeValue\": \"US\",\r\n" + 
				"					\"uiControlType\": \"DropDown\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 23,\r\n" + 
				"					\"questionId\": 85,\r\n" + 
				"					\"tfsUIDesc\": \"Country Code\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP100012\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000026\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Site\",\r\n" + 
				"					\"prvGroupId\": 1,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339275,\r\n" + 
				"					\"itemName\": \"Webex Core\",\r\n" + 
				"					\"attributeName\": \"TIME ZONE\",\r\n" + 
				"					\"attributeValue\": \"(GMT -08:00) PACIFIC TIME,USA & CANADA\",\r\n" + 
				"					\"uiControlType\": \"DropDown\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 24,\r\n" + 
				"					\"questionId\": 83,\r\n" + 
				"					\"tfsUIDesc\": \"Time Zone\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP100018\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000026\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Site\",\r\n" + 
				"					\"prvGroupId\": 1,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339276,\r\n" + 
				"					\"itemName\": \"Webex Core\",\r\n" + 
				"					\"attributeName\": \"PRIMARY LANGUAGE\",\r\n" + 
				"					\"attributeValue\": \"en_US\",\r\n" + 
				"					\"uiControlType\": \"DropDown\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Horizontal\",\r\n" + 
				"					\"displayOrder\": 25,\r\n" + 
				"					\"questionId\": 86,\r\n" + 
				"					\"tfsUIDesc\": \"Primary Language\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP100002\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000026\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Site\",\r\n" + 
				"					\"prvGroupId\": 1,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339277,\r\n" + 
				"					\"itemName\": \"Webex Core\",\r\n" + 
				"					\"attributeName\": \"ADDITIONAL LANGUAGES\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"ComboBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Horizontal\",\r\n" + 
				"					\"displayOrder\": 26,\r\n" + 
				"					\"questionId\": 87,\r\n" + 
				"					\"tfsUIDesc\": \"Would you like to enable additional languages?\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"N\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP100004\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000026\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Site\",\r\n" + 
				"					\"prvGroupId\": 1,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339278,\r\n" + 
				"					\"itemName\": \"Webex Conferencing\",\r\n" + 
				"					\"attributeName\": \"SERVICE ENABLED\",\r\n" + 
				"					\"attributeValue\": \"true\",\r\n" + 
				"					\"uiControlType\": \"RadioButton\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 27,\r\n" + 
				"					\"questionId\": 114,\r\n" + 
				"					\"tfsUIDesc\": \"Enable Meeting Center?\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP000057\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000026\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Site\",\r\n" + 
				"					\"prvGroupId\": 1,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339279,\r\n" + 
				"					\"itemName\": \"Webex Conferencing\",\r\n" + 
				"					\"attributeName\": \"LICENSE VOLUME\",\r\n" + 
				"					\"attributeValue\": \"10\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 28,\r\n" + 
				"					\"questionId\": 113,\r\n" + 
				"					\"tfsUIDesc\": \"Meeting Center Licenses\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP000062\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000026\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Site\",\r\n" + 
				"					\"prvGroupId\": 1,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 534757,\r\n" + 
				"					\"itemName\": \"Webex EE\",\r\n" + 
				"					\"attributeName\": \"SERVICE ENABLED\",\r\n" + 
				"					\"attributeValue\": \"true\",\r\n" + 
				"					\"uiControlType\": \"RadioButton\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 29,\r\n" + 
				"					\"questionId\": 79,\r\n" + 
				"					\"tfsUIDesc\": \"Enable Enterprise Edition?\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP000055\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000026\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Site\",\r\n" + 
				"					\"prvGroupId\": 1,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"02/20/2020\",\r\n" + 
				"					\"puiEntryOn\": \"02/20/2020\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 534759,\r\n" + 
				"					\"itemName\": \"Webex EE\",\r\n" + 
				"					\"attributeName\": \"LICENSE VOLUME\",\r\n" + 
				"					\"attributeValue\": null,\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 30,\r\n" + 
				"					\"questionId\": 78,\r\n" + 
				"					\"tfsUIDesc\": \"Enterprise Edition Licenses\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": \"CP000060\",\r\n" + 
				"					\"uiGroupLabel\": \"CP000026\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Site\",\r\n" + 
				"					\"prvGroupId\": 1,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"02/20/2020\",\r\n" + 
				"					\"puiEntryOn\": \"02/20/2020\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 534761,\r\n" + 
				"					\"itemName\": \"Webex CMR\",\r\n" + 
				"					\"attributeName\": \"SERVICE ENABLED\",\r\n" + 
				"					\"attributeValue\": \"true\",\r\n" + 
				"					\"uiControlType\": \"RadioButton\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 35,\r\n" + 
				"					\"questionId\": 82,\r\n" + 
				"					\"tfsUIDesc\": \"Enable CMR?\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000026\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Site\",\r\n" + 
				"					\"prvGroupId\": 1,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"02/20/2020\",\r\n" + 
				"					\"puiEntryOn\": \"02/20/2020\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 534763,\r\n" + 
				"					\"itemName\": \"Webex CMR\",\r\n" + 
				"					\"attributeName\": \"LICENSE VOLUME\",\r\n" + 
				"					\"attributeValue\": null,\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 36,\r\n" + 
				"					\"questionId\": 81,\r\n" + 
				"					\"tfsUIDesc\": \"CMR Licenses\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000026\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Site\",\r\n" + 
				"					\"prvGroupId\": 1,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"02/20/2020\",\r\n" + 
				"					\"puiEntryOn\": \"02/20/2020\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				}\r\n" + 
				"			]\r\n" + 
				"		},\r\n" + 
				"		{\r\n" + 
				"			\"groupId\": 15,\r\n" + 
				"			\"groupName\": \"IM Org Information\",\r\n" + 
				"			\"groupCode\": \"IM Org Information\",\r\n" + 
				"			\"type\": null,\r\n" + 
				"			\"prvId\": 23738,\r\n" + 
				"			\"webOrderId\": \"381547193\",\r\n" + 
				"			\"transactionId\": 3809281,\r\n" + 
				"			\"userId\": \"yhargrove\",\r\n" + 
				"			\"majorLineTransactionId\": 3809282,\r\n" + 
				"			\"attributeDetails\": [\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339280,\r\n" + 
				"					\"itemName\": \"Webex Common\",\r\n" + 
				"					\"attributeName\": \"ORGANIZATION NAME\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 11,\r\n" + 
				"					\"questionId\": 92,\r\n" + 
				"					\"tfsUIDesc\": \"Organization Name\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000008\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339281,\r\n" + 
				"					\"itemName\": \"Webex Messenger\",\r\n" + 
				"					\"attributeName\": \"DOMAIN NAME LIST\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"Domain\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 12,\r\n" + 
				"					\"questionId\": 102,\r\n" + 
				"					\"tfsUIDesc\": \"Domain Name List (Use ; for multiple values)\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000008\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339282,\r\n" + 
				"					\"itemName\": \"Webex Messenger\",\r\n" + 
				"					\"attributeName\": \"ORG ADMIN EMAIL\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"Email\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 13,\r\n" + 
				"					\"questionId\": 101,\r\n" + 
				"					\"tfsUIDesc\": \"Org Admin eMail\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000008\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339283,\r\n" + 
				"					\"itemName\": \"Webex Messenger\",\r\n" + 
				"					\"attributeName\": \"ORG ADMIN FIRST NAME\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 14,\r\n" + 
				"					\"questionId\": 105,\r\n" + 
				"					\"tfsUIDesc\": \"Org Admin First Name\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000008\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339284,\r\n" + 
				"					\"itemName\": \"Webex Messenger\",\r\n" + 
				"					\"attributeName\": \"ORG ADMIN LAST NAME\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 15,\r\n" + 
				"					\"questionId\": 104,\r\n" + 
				"					\"tfsUIDesc\": \"Org Admin Last Name\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000008\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339285,\r\n" + 
				"					\"itemName\": \"Webex Messenger\",\r\n" + 
				"					\"attributeName\": \"ORG ADMIN PHONE NUMBER\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 128,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 16,\r\n" + 
				"					\"questionId\": 106,\r\n" + 
				"					\"tfsUIDesc\": \"Org Admin Phone Number (eg. 1-(408) 555-1212 ext 123)\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000008\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339286,\r\n" + 
				"					\"itemName\": \"Webex Messenger\",\r\n" + 
				"					\"attributeName\": \"IM LOGGING\",\r\n" + 
				"					\"attributeValue\": \"true\",\r\n" + 
				"					\"uiControlType\": \"RadioButton\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Horizontal\",\r\n" + 
				"					\"displayOrder\": 17,\r\n" + 
				"					\"questionId\": 99,\r\n" + 
				"					\"tfsUIDesc\": \"Enable IM Logging (server side)?\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000008\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339287,\r\n" + 
				"					\"itemName\": \"Webex Messenger\",\r\n" + 
				"					\"attributeName\": \"INTEGRATION TYPE\",\r\n" + 
				"					\"attributeValue\": \"loose\",\r\n" + 
				"					\"uiControlType\": \"RadioButton\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Sideways\",\r\n" + 
				"					\"displayOrder\": 18,\r\n" + 
				"					\"questionId\": 103,\r\n" + 
				"					\"tfsUIDesc\": \"If Conferencing and Messenger are on the same subscription, then Integration Type reference is needed\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"N\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000008\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339288,\r\n" + 
				"					\"itemName\": \"Webex Messenger\",\r\n" + 
				"					\"attributeName\": \"UC INTEGRATION\",\r\n" + 
				"					\"attributeValue\": \"false\",\r\n" + 
				"					\"uiControlType\": \"RadioButton\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Horizontal\",\r\n" + 
				"					\"displayOrder\": 19,\r\n" + 
				"					\"questionId\": 100,\r\n" + 
				"					\"tfsUIDesc\": \"Would you like to integrate with Cisco Unified Communications Manager?\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000008\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				}\r\n" + 
				"			]\r\n" + 
				"		},\r\n" + 
				"		{\r\n" + 
				"			\"groupId\": 17,\r\n" + 
				"			\"groupName\": \"Site Admin Info\",\r\n" + 
				"			\"groupCode\": \"Site Information\",\r\n" + 
				"			\"type\": null,\r\n" + 
				"			\"prvId\": 23738,\r\n" + 
				"			\"webOrderId\": \"381547193\",\r\n" + 
				"			\"transactionId\": 3809281,\r\n" + 
				"			\"userId\": \"yhargrove\",\r\n" + 
				"			\"majorLineTransactionId\": 3809282,\r\n" + 
				"			\"attributeDetails\": [\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339289,\r\n" + 
				"					\"itemName\": \"Webex Common\",\r\n" + 
				"					\"attributeName\": \"ADMIN EMAIL\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"Email\",\r\n" + 
				"					\"controlTypeArrangement\": \"Horizontal\",\r\n" + 
				"					\"displayOrder\": 7,\r\n" + 
				"					\"questionId\": 89,\r\n" + 
				"					\"tfsUIDesc\": \"Site Admin Contact eMail\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP100009\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339290,\r\n" + 
				"					\"itemName\": \"Webex Common\",\r\n" + 
				"					\"attributeName\": \"ADMIN FIRST NAME\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Horizontal\",\r\n" + 
				"					\"displayOrder\": 8,\r\n" + 
				"					\"questionId\": 91,\r\n" + 
				"					\"tfsUIDesc\": \"Site Admin First Name\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP100009\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339291,\r\n" + 
				"					\"itemName\": \"Webex Common\",\r\n" + 
				"					\"attributeName\": \"ADMIN LAST NAME\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Horizontal\",\r\n" + 
				"					\"displayOrder\": 9,\r\n" + 
				"					\"questionId\": 90,\r\n" + 
				"					\"tfsUIDesc\": \"Site Admin Last Name\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP100009\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339292,\r\n" + 
				"					\"itemName\": \"Webex Common\",\r\n" + 
				"					\"attributeName\": \"ADMIN PHONE NUMBER\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 128,\r\n" + 
				"					\"dataType\": \"String\",\r\n" + 
				"					\"controlTypeArrangement\": \"Horizontal\",\r\n" + 
				"					\"displayOrder\": 10,\r\n" + 
				"					\"questionId\": 93,\r\n" + 
				"					\"tfsUIDesc\": \"Site Admin Phone Number (eg. 1-(408) 555-1212 ext 123\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"WO\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP100009\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				}\r\n" + 
				"			]\r\n" + 
				"		},\r\n" + 
				"		{\r\n" + 
				"			\"groupId\": 18,\r\n" + 
				"			\"groupName\": \"Management Portal Access\",\r\n" + 
				"			\"groupCode\": \"Management Portal Access\",\r\n" + 
				"			\"type\": null,\r\n" + 
				"			\"prvId\": 23738,\r\n" + 
				"			\"webOrderId\": \"381547193\",\r\n" + 
				"			\"transactionId\": 3809281,\r\n" + 
				"			\"userId\": \"yhargrove\",\r\n" + 
				"			\"majorLineTransactionId\": 3809282,\r\n" + 
				"			\"attributeDetails\": [\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339293,\r\n" + 
				"					\"itemName\": \"Contacts\",\r\n" + 
				"					\"attributeName\": \"END CUSTOMER EMAIL\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 1,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"Email\",\r\n" + 
				"					\"controlTypeArrangement\": \"Horizontal\",\r\n" + 
				"					\"displayOrder\": 1,\r\n" + 
				"					\"questionId\": 71,\r\n" + 
				"					\"tfsUIDesc\": \"End Customer Admin Email\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000039\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339294,\r\n" + 
				"					\"itemName\": \"Contacts\",\r\n" + 
				"					\"attributeName\": \"PARTNER ADMIN EMAIL\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"Email\",\r\n" + 
				"					\"controlTypeArrangement\": \"Horizontal\",\r\n" + 
				"					\"displayOrder\": 3,\r\n" + 
				"					\"questionId\": 72,\r\n" + 
				"					\"tfsUIDesc\": \"Tier-1 Reseller Admin Email\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"Y\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000039\",\r\n" + 
				"					\"guideTextLabel\": null,\r\n" + 
				"					\"guideTextMessage\": null,\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				},\r\n" + 
				"				{\r\n" + 
				"					\"prvAttrId\": 339295,\r\n" + 
				"					\"itemName\": \"Contacts\",\r\n" + 
				"					\"attributeName\": \"RESELLER ADMIN EMAIL\",\r\n" + 
				"					\"attributeValue\": \"\",\r\n" + 
				"					\"uiControlType\": \"TextBox\",\r\n" + 
				"					\"minLength\": 0,\r\n" + 
				"					\"maxLength\": 256,\r\n" + 
				"					\"dataType\": \"Email\",\r\n" + 
				"					\"controlTypeArrangement\": \"Horizontal\",\r\n" + 
				"					\"displayOrder\": 5,\r\n" + 
				"					\"questionId\": 73,\r\n" + 
				"					\"tfsUIDesc\": \"Tier-2 Reseller Admin Email\",\r\n" + 
				"					\"parentId\": null,\r\n" + 
				"					\"mandatory\": \"N\",\r\n" + 
				"					\"editableForNew\": \"RW\",\r\n" + 
				"					\"editableForChange\": \"RW\",\r\n" + 
				"					\"tfsUIDescLabel\": null,\r\n" + 
				"					\"uiGroupLabel\": \"CP000039\",\r\n" + 
				"					\"guideTextLabel\": \"CD000176\",\r\n" + 
				"					\"guideTextMessage\": \"In this context, a &quot;Reseller&quot; is an entity which does business through a Distributor\",\r\n" + 
				"					\"existingAttribute\": \"N\",\r\n" + 
				"					\"logicalDelete\": \"N\",\r\n" + 
				"					\"validationFlag\": \"Y\",\r\n" + 
				"					\"serviceGroup\": \"Common\",\r\n" + 
				"					\"prvGroupId\": null,\r\n" + 
				"					\"createdBy\": \"yhargrove\",\r\n" + 
				"					\"createdOn\": \"05/13/2017\",\r\n" + 
				"					\"updatedBy\": \"yhargrove\",\r\n" + 
				"					\"updatedOn\": \"03/23/2021\",\r\n" + 
				"					\"puiEntryOn\": \"06/11/2017\",\r\n" + 
				"					\"status\": null\r\n" + 
				"				}\r\n" + 
				"			]\r\n" + 
				"		}\r\n" + 
				"	]\r\n" + 
				"}";
		boolean flag=SecurityContants.isVulnerabilityCheckPoint(payload);
		System.out.println("Valid Payload:{}"+flag);
	}
	
	@Test
	public void testAllowedHeaders() {
		String allowedHeaders="X-RTC-AUTH|X-RTC-SCANID|X-RTC-REQUESTID";
		String value="X-RTC-REQUESTID";
		StringBuilder headersRegex=new StringBuilder();
		headersRegex.append("\\b").append("(").append(allowedHeaders).append(")\\b");
		setAllowedHeadersRegex(headersRegex.toString());
		boolean flag=SecurityContants.isValidHeader(value);
		System.out.println("Allowed Header Flag:{}"+flag);
	}
	
	@Test
	public void testCrosHeaders() {
		String allowedHeaders="https://software-dev.cisco.com,https://swapi-dev.cisco.com,http://localhost,http://localhost:8080,http://cda-ui,https://cloudsso-test.cisco.com,https://activate-dev-rtp.cisco.com,https://api-345c0691.duosecurity.com";
		String value="http://localhost";
		boolean flag=SecurityContants.isValidCorsUrls(allowedHeaders,value);
		System.out.println("Allowed Header Flag:{}"+flag);
	}
	
	@Test
	public void testHeaderInjections(){
		String path="x-envoy-original-path=/software/services/swiftlrpsvcs/getRehostTargetDeviceDtls?requestType=%25REHOST%25&subgroup=NEXUS1KHYPERVFEAT";
		path=SecurityContants.percentDecode(path);
		System.out.print("Path:{}"+path);
		System.out.println("Path:{}"+SecurityContants.isVulnerabilityCheckPoint(path));
	}
}
