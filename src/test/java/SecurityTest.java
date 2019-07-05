import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.junit.Test;

public class SecurityTest {

	private final Logger LOGGER=Logger.getLogger(SecurityTest.class);
	
	@Test
	public void sqlInjectionTest() {
	   //String cecId=" '' || '' || 'umprasad%40cisco.com'";
		//() { A;}>A[$($())] { /bin/sleep 181;}
	   String queryString="accept=image/webp,image/apng,image/*,*/*;q=0.8";
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
			sqlStatement.append("|sleep\\(.*\\)|sleep\\s?[0-9A-Za-z]");
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
