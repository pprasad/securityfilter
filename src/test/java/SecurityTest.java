import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.junit.Test;

public class SecurityTest {

	private final Logger LOGGER=Logger.getLogger(SecurityTest.class);
	
	@Test
	public void sqlInjectionTest() throws UnsupportedEncodingException {
	   //String cecId=" '' || '' || 'umprasad%40cisco.com'";
		//() { A;}>A[$($())] { /bin/sleep 181;}
	   String queryString="selSubgroup=800FIXEDFEAT&selectedSubgroup=800FIXEDFEAT&ARCBANSAL=AIR-CT5508-100-K9&screenName=createpakoperations&userId=&keyType=CREATEPAK&actionValue=&buttonPressed=Issue+PAK&featureOption=%5B%5D&featureQty=%5B%5D&locale=en_US&dispLicDatesFlag=false&dispProdQTYFlag=true&subGrpQTY=N&selectedSourceCAId=-1&selectedSourceCAName=&selectedSourceVAId=-1&selectedSourceVAName=&product_type=safenet&addressFlag=&cprWebData=&PRODUCTDESC=800-NR-TEST&features=C1-SL-1100-4P-APP&__multiselect_features=&noOfPaks=&hidden_pak_pref_val=MULTIPLE%3AN&Option0=C1-SL-1100-4P-APP+%3A+AppX+Foundation+License+for+Cisco+ISR+1100+4P+Series&qty0=1&Option1=&qty1=%3C%00script%3E%5Bwindow%5B%22location%22%5D%3D%22%5Cx6a%5Cx61%5Cx76%5Cx61%5Cx73%5Cx63%5Cx72%5Cx69%5Cx70%5Cx74%5Cx3a%5Cx61%5Cx6c%5Cx65%5Cx72%5Cx74%5Cx28204%5Cx29%22%5D%3C%2Fscript+%3E&Option2=&qty2=&Option3=&qty3=&Option4=&qty4=&ccoId=saiupadh&EMAIL=saiupadh%40cisco.com&SALESORDNO=SalesOrder&SUBSCRIPTIONID=&TACCASE=NA&NOTES=";
	  // queryString=URLDecoder.decode(queryString.trim(), "UTF-8");
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
	
	private boolean isVulnerability(String requestData) {
		boolean flag=true;
		if(requestData!=null){
			StringBuilder sqlStatement=new StringBuilder();
			sqlStatement.append("\\bselect\\b|\\binsert\\b|having\\s?[count]|drop|union[\\s]?\\b(select|delete|insert|delete)\\b|(\'|%27).(and|or|AND|OR).(\'|%27)|(\'|%27).%7C{0,2}|%7C{2}");
			sqlStatement.append("|\\bmerge\\b|\\border by\\b|INSERT( +INTO){0,1}|EXEC(UTE){0,1}");
			sqlStatement.append("|<script>(.*?)</script>|src[\r\n]*=[\r\n]*\\'(.*?)\\'");
			sqlStatement.append("|</script>|<script(.*?)>|eval\\((.*?)\\)|expression\\((.*?)\\)|javascript:|alert\\((.*?)\\)");
			sqlStatement.append("|<!--|\\b#include\\b|\\bfile\\b|\\b/etc/passwd\\b|-->|\\bjsessionid:\\b|\\bJSESSIONID:\\b|\\bvbscript:\\b|onload(.*?)=|/\\*([^*]|[\r\n]|(\\*+([^*/]|[\r\n])))*\\*+/");
			sqlStatement.append("|/\\*(?:.|[\\n\\r])*?\\*/|--[^\r\n]*|((\\%3C)|<)((\\%69)|i|(\\%49))((\\%6D)|m|(\\%4D))((\\%67)|g|(\\%47))[^\n]+((\\%3E)|>)");
			sqlStatement.append("|\\(function\\(\\)\\{.*\\}\\)\\(\\)|\\(function\\(\\)\\)\\(\\)");
			sqlStatement.append("|[\\\"\\\'][\\s]*javascript:(.*)[\\\"\\\']|(?i)<script.*?>.*?<script.*?>|(?i)<.*?javascript:.*?>.*?</.*?>|(?i)<.*?\\s+on.*?>.*?</.*?>");
			sqlStatement.append("|;vol|&&ls *");
			sqlStatement.append("|\\$query*");
			sqlStatement.append("|sleep\\(.*\\)|sleep\\s?[0-9A-Za-z]|(<input(.*?)></input>|<input(.*)/>)");
			sqlStatement.append("|%3C%00script.*|%3cscript.*");
			sqlStatement.append("|ltrim");
			Pattern p = Pattern.compile(sqlStatement.toString(),Pattern.CASE_INSENSITIVE);
	        Matcher m = p.matcher(requestData);
			if(m.find()){
				flag=false;
			}
    	}else{
    		flag=true;
    	}
		return flag;
	}	
}
