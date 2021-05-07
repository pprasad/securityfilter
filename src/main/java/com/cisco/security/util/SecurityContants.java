package com.cisco.security.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.FilterConfig;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecurityContants {
	
	private static final Logger LOGGER=LoggerFactory.getLogger(SecurityContants.class);
	
	private static final String CISCO_LIFE="CISCO_LIFE";
	    
	private static final String ENV_TYPE="cisco.life";
	
	private static final String HTTP_ONLY="; HttpOnly;";
	
    public static boolean isVulnerabilityCheckPoint(String requestData) {
    	boolean flag=true;
    	LOGGER.info("**********Started VulnerabilityCheckPoint********************");
    	StringBuilder sqlStatement=new StringBuilder();
    	sqlStatement.append("';|;--|\\b(ALTER|CREATE\\s?(TABLE|VALUES)|DELETE\\s?(FROM|SELECT|WHERE)|DROP|EXEC(UTE){0,1}|INSERT( +INTO){0,1}|MERGE|SELECT|UPDATE\\s?(SET)|UNION( +ALL){0,1}(SELECT)|HAVING\\s?(COUNT|GROUP BY)|ORDER BY)\\b");
    	sqlStatement.append("|(\'|%27).(and|or|AND|OR).(\'|%27)|(\'|%27).%7C{0,2}|%7C{2}");
    	sqlStatement.append("|<script>(.*?)</script>|src[\r\n]*=[\r\n]*\\'(.*?)\\'");
		sqlStatement.append("|</script>|<script(.*?)>|eval\\((.*?)\\)|expression\\((.*?)\\)|javascript:|alert\\((.*?)\\)");
		sqlStatement.append("|\\b#include\\b|\\bfile(=|:)\\b|\\b/etc/passwd\\b|\\bjsessionid:\\b|\\bJSESSIONID:\\b|\\bvbscript:\\b|onload(.*?)=");
		sqlStatement.append("|\\b--\\b|((\\%3C)|<)((\\%69)|i|(\\%49))((\\%6D)|m|(\\%4D))((\\%67)|g|(\\%47))[^\n]+((\\%3E)|>)");
		sqlStatement.append("|\\(function\\(\\)\\{.*\\}\\)\\(\\)|\\(function\\(\\)\\)\\(\\)");
		sqlStatement.append("|[\\\"\\\'][\\s]*javascript:(.*)[\\\"\\\']|(?i)<script.*?>.*?<script.*?>|(?i)<.*?javascript:.*?>.*?</.*?>|(?i)<.*?\\s+on.*?>.*?</.*?>");
		sqlStatement.append("|;vol|&&ls *");
		sqlStatement.append("|\\$query*");
		sqlStatement.append("|sleep\\(.*\\)|sleep\\s?[0-9A-Za-z]|(<input(.*?)></input>|<input(.*)/>)");
		sqlStatement.append("|%3C%00script.*|%3cscript.*|< script>.*?</script >|%3C+.*|(%25|%25.*)|iframe|window.*(location|src)|<a herf=.*?>(.*?)</a>");
		sqlStatement.append("|ltrim");
		Pattern p = Pattern.compile(sqlStatement.toString(),Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(requestData);
		if(m.find()){
			flag=false;
		}
    	LOGGER.info("**********End VulnerabilityCheckPoint********************");
    	return flag;
    }
    public static String getPath(String url) {
    	String urlPath=null;
    	String path[]=url.split("/");
		int len=path.length-1;
		if(len!=-1){
		   urlPath=path[len];
	       LOGGER.info("paths::{}"+path.length+"  path[path.length-1]::{}"+urlPath);
	       LOGGER.info("Execulde URL:{}"+urlPath);
	       return urlPath;
		}else{
		    LOGGER.info("Execulde URL:{}"+url);
		    return url;
		}
    }
    public static String getEnvType() {
    	String envType=System.getProperty(ENV_TYPE);
    	LOGGER.info("Env Type:{}"+envType);
    	if(envType==null){
    		envType=System.getenv(ENV_TYPE);
    		envType=envType!=null?envType:System.getenv(CISCO_LIFE);
    	}
    	LOGGER.info("Cisco Life:{}"+envType);
    	return envType;
    }
    public static boolean isValidRefererHeader(String value,String allowedReferers){
    	LOGGER.info("**********Started isValidRefererHeader********************");
    	LOGGER.info("Allowed Refereres Headers{}"+allowedReferers);
    	LOGGER.info("Received Referer Header{}"+value);
    	boolean flag=false;
    	if(value!=null && allowedReferers!=null){
	    	allowedReferers=allowedReferers.replaceAll(",","|");
	    	StringBuilder refererHeaders=new StringBuilder();
	    	refererHeaders.append("\\b");
	    	refererHeaders.append("((http(s\\:\\/\\/|\\:\\/\\/))(");
	    	refererHeaders.append(allowedReferers);
	    	refererHeaders.append("))\\b");
	    	Pattern pattern=Pattern.compile(refererHeaders.toString(),Pattern.DOTALL);
	    	Matcher match=pattern.matcher(value);
	    	if(match.find()) {
	    		flag=true;
	    	}
    	}
    	LOGGER.info("**********End isValidRefererHeader********************");
    	return flag;
    }
    public static boolean isValidURL(String value){
    	LOGGER.info("**********Started isValidURL********************");
    	boolean flag=false;
    	if(value!=null){
	    	StringBuilder hostUrls=new StringBuilder();
	    	hostUrls.append("\\b(cisco.com|webex.com)\\b");
	    	Pattern pattern=Pattern.compile(hostUrls.toString(),Pattern.CASE_INSENSITIVE);
	    	Matcher match=pattern.matcher(value);
	    	if(match.find()) {
	    		flag=true;
	    	}
    	}
    	LOGGER.info("**********End isValidURL********************");
    	return flag;
    }
    public static String getSystemValues(FilterConfig config,String key){
    	String value=config.getInitParameter(key);
    	value=(value==null)?System.getProperty(key):value;
		if(value==null) {
			value=System.getenv(key);
		}
		return value;
	}
    public static void setSecureCookie(HttpServletResponse response,Cookie cookie) {
    	   if(!cookie.getSecure()){
			  cookie.setSecure(true);
			  cookie.setComment(HTTP_ONLY);
			  response.addCookie(cookie);
		   }else if(cookie.getComment()==null || !HTTP_ONLY.equals(cookie.getComment())){
			  cookie.setComment(HTTP_ONLY);
			  response.addCookie(cookie);
		   }
    }
}