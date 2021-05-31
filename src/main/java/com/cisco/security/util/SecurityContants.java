package com.cisco.security.util;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.FilterConfig;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class SecurityContants {
	
	private static final Logger LOGGER=LoggerFactory.getLogger(SecurityContants.class);
	
	private static final String CISCO_LIFE="CISCO_LIFE";
	    
	private static final String ENV_TYPE="cisco.life";
	
	private static final String HTTP_ONLY="; HttpOnly;";
	
	private static final List<String> excludeHeaderValues=new ArrayList<String>();
	
	private static final List<String> excludeQueryParams=new ArrayList<String>();
	
	private static final List<String> excludeHeaders=new ArrayList<String>();
	
	private static String allowedHeadersRegex=null;
	
	private SecurityContants(){ }
		
    public static boolean isVulnerabilityCheckPoint(String requestData) {
    	boolean flag=true;
    	LOGGER.info("**********Started VulnerabilityCheckPoint********************");
    	StringBuilder sqlStatement=new StringBuilder();
    	sqlStatement.append("';|;--|\\b(ALTER|CREATE\\s?(TABLE|VALUES)|DELETE\\s?(FROM|SELECT|WHERE)|DROP|EXEC(UTE){0,1}|INSERT( +INTO){0,1}|MERGE|SELECT\\s?(FROM|WHERE|=|;DROP TABLE)|UPDATE\\s?(SET)|UNION( +ALL){0,1}(SELECT)|HAVING\\s?(COUNT|GROUP BY)|ORDER BY)\\b");
    	sqlStatement.append("|(\'|%27).(and|or|AND|OR).(\'|%27)|(\'|%27).%7C{0,2}|%7C{2}");
    	sqlStatement.append("|<script>(.*?)</script>|src[\r\n]*=[\r\n]*\\'(.*?)\\'");
		sqlStatement.append("|</script>|<script(.*?)>|eval\\((.*?)\\)|expression\\((.*?)\\)|javascript:|alert\\((.*?)\\)");
		sqlStatement.append("|\\b#include\\b|\\bfile(=|:)\\b|\\b/etc/passwd\\b|\\bjsessionid:\\b|\\bJSESSIONID:\\b|\\bvbscript:\\b|onload(.*?)=");
		sqlStatement.append("|\\b--\\b|((\\%3C)|<)((\\%69)|i|(\\%49))((\\%6D)|m|(\\%4D))((\\%67)|g|(\\%47))[^\n]+((\\%3E)|>)");
		sqlStatement.append("|\\(function\\(\\)\\{.*\\}\\)\\(\\)|\\(function\\(\\)\\)\\(\\)");
		sqlStatement.append("|[\\\"\\\'][\\s]*javascript:(.*)[\\\"\\\']|(?i)<script.*?>.*?<script.*?>|(?i)<.*?javascript:.*?>.*?</.*?>|(?i)<.*?\\s+on.*?>.*?</.*?>");
		sqlStatement.append("|;vol|&&ls *|--[^\r\n]*|'[^\\\\_0-9a-zA-B]+");
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
    public static boolean isValidHeader(String value) {
    	boolean flag=false;
    	LOGGER.info("**************isValidHeader**************");
    	LOGGER.info("Header Name:{}",value);
    	if(allowedHeadersRegex!=null && (value!=null && value.toLowerCase().startsWith("x-"))){
    		Pattern pattern=Pattern.compile(allowedHeadersRegex,Pattern.CASE_INSENSITIVE);
	    	Matcher match=pattern.matcher(value);
	    	if(match.find()) {
	    		flag=true;
	    	}
    	}else if(value!=null && !value.toLowerCase().startsWith("x-")){
    		flag=true;
    	}
    	LOGGER.info("Allow status {} for Header {}",flag,value);
    	return flag;
    }
    
    public static boolean isValidCorsUrls(String allowedOriginHeaders,String value){
    	LOGGER.info("**********Started isValidCorsUrls********************");
    	LOGGER.info("Application Allowed Cross Origin URLS{}",allowedOriginHeaders);
    	LOGGER.info("Cors Origin URL{}",value);
    	boolean flag=false;
    	if(allowedOriginHeaders!=null && value!=null) {
    		StringBuilder headersRegex=new StringBuilder();
			headersRegex.append("\\b").append("(").append(String.join("|",allowedOriginHeaders.split(","))).append(")\\b");
			Pattern pattern=Pattern.compile(headersRegex.toString(),Pattern.DOTALL);
	    	Matcher match=pattern.matcher(value);
	    	if(match.find()) {
	    		flag=true;
	    	}
    	}else if(value==null) {
    		flag=true;
    	}
    	LOGGER.info(" Valid CorsUrl Status:{} & URL:{}",flag,value);
    	LOGGER.info("**********End isValidCorsUrls********************");
    	return flag;
    }

    public static String percentDecode(String value) {
    	 if(value==null) {
    		 return value;
    	 }else{
    		 String decoded =value.replace("%21","!");
    		 decoded = decoded.replace("%20"," ");
    		 decoded = decoded.replace("%23","#");
    		 decoded = decoded.replace("%24","$");
    		 decoded = decoded.replace("%26","&");
    		 decoded = decoded.replace("%27","'");
    		 decoded = decoded.replace("%28","(");
    		 decoded = decoded.replace("%29",")");
    		 decoded = decoded.replace("%2A","*");
    		 decoded = decoded.replace("%2B","+");
    		 decoded = decoded.replace("%2C",",");
    		 decoded = decoded.replace("%2F","/");
    		 decoded = decoded.replace("%3A",":");
    		 decoded = decoded.replace("%3B",";");
    		 decoded = decoded.replace("%3D","=");
    		 decoded = decoded.replace("%3F","?");
    		 decoded = decoded.replace("%40","@");
    		 decoded = decoded.replace("%5B","[");
    		 decoded = decoded.replace("%5D","]");
    		 decoded = decoded.replace("%25","%");
    		 return decoded; 
    	 }
    }
    public static String decodeHeaderValue(String key,String value){
    	if(excludeHeaderValues!=null && !excludeHeaderValues.isEmpty() && excludeHeaderValues.contains(key)) {
    	    return percentDecode(value);
    	 }else{
    		return value;
    	 }
    }
    public static boolean isEmpty(String value) {
    	return (value!=null && !value.trim().isEmpty())?false:true;
    }
    
    public static boolean isExcludeQueryParams(String key){
    	return !excludeQueryParams.isEmpty() && excludeQueryParams.contains(key);
    }
    
    public static boolean isExcludeHeader(String key) {
    	return !excludeHeaders.isEmpty() && excludeHeaders.contains(key);
    }
    
    public static void addExcludeHeaderValues(FilterConfig config,String key) {
    	String values=getSystemValues(config,key);
		if(!isEmpty(values)){
			for(String s:values.split(",")){
				SecurityContants.excludeHeaderValues.add(s);
	    	}
		}
    }
    
    public static void addExcludeQueryParams(FilterConfig config,String key){
    	String values=getSystemValues(config,key);
		if(!isEmpty(values)){
			for(String s:values.split(",")){
		    	SecurityContants.excludeQueryParams.add(s);
	    	}
		}
    }

    public static void setAllowedHeadersRegex(String allowedHeadersRegex) {
		SecurityContants.allowedHeadersRegex = allowedHeadersRegex;
	}

	public static List<String> getExcludeheadervalues() {
		return excludeHeaderValues;
	}

	public static List<String> getExcludequeryparams() {
		return excludeQueryParams;
	}
	
	public static void addExcludeHeaders(FilterConfig config,String key) {
		String values=getSystemValues(config,key);
		if(!isEmpty(values)){
			for(String s:values.split(",")){
		    	SecurityContants.excludeHeaders.add(s);
	    	}
		}
	}
	public static List<String> getExcludeheaders() {
		return excludeHeaders;
	}

	public static String prepareErrorMessage(boolean isValidHeader,boolean isValidMethod,boolean isValidBody,boolean isValidQueryParams){
		String errorMsg=null;
		if(!isValidHeader) {
			errorMsg="Invalid Header Values";
		}else if(!isValidMethod) {
			errorMsg="Invalid Method";
		}else if(!isValidBody) {
			errorMsg="Invalid Body Request";
		}else if(!isValidQueryParams) {
			errorMsg="Invalid Query Parameters";
		}
		return errorMsg;
	}
}