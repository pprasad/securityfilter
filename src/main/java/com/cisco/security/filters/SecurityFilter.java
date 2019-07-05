package com.cisco.security.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
/*
 * @Auth : umprasad
 * @Desc : Vulnerability filter it will does't allowed SQL,CSS & javascript injections
 */
public class SecurityFilter implements Filter {
	
	private final static Logger LOGGER=Logger.getLogger(SecurityFilter.class);

	private final String EMAN_URL="EMAN_URL";
	
	private final String SESSION_ID="JSESSIONID";
	
	private final String HTTP_ONLY="; HttpOnly;";
	
	private final String OBSSO_COOKIE="ObSSOCookie";
	
    private final String GEAR_COOKIE="GEAR";
    
    private final String SERVERID_COOKIE="SERVERID";
    
    private final String CISCO_DOMAIN="cisco.com";
	
	private final String WEBEX_DOMAIN="webex.com";
	
	private final String IS_SECURITY_RUN="IS_SECURITY_RUN";
	
	private final String IS_SECURITY_RUN_YES="Y";
	
	private final String IS_SECURITY_RUN_NO="N";
	
	protected final String INVALID_REQUEST= "InValid Request";
	
	private final String ALLOW_CONTEXT_PATH="ALLOW_CONTEXT_PATH";
	
	protected final String ALLOW_HOSTS="ALLOW_HOSTS";
	
	protected final String EDOS_LOGIN_COOKIE="edosLogin";
	
    protected final String ACCESS_DENIDED= "Access to this feature is restricted outside of the Cisco Commerce Subscription Workbench and SSW applications";
    
    private final String APP_COOKIES="APP_COOKIES";
    
    private final String EDOS_AMCV_COOKIE="AMCV_B8D07FF4520E94C10A490D4C%40AdobeOrg";
    
    private final String METHOD_ALLOWED="METHOD_ALLOWED";
	
	private String emanURL=null;
	
	private List<String> allowHosts;
	
	private String allowContextPath=null;
	
	private List<String> appCookies;
	
	private List<String> ALLOW_METHODS;
	
    public void init(FilterConfig config) throws ServletException {
		emanURL=config.getInitParameter(EMAN_URL);
		if(emanURL==null){emanURL=getEnvironments(EMAN_URL);}
		String allowHost=getEnvironments(ALLOW_HOSTS);
		String methodAllows=config.getInitParameter("METHOD_ALLOWED");
		if(methodAllows==null){methodAllows=getEnvironments(METHOD_ALLOWED);}
		/*Allowed HostURL*/
		if(allowHost!=null) {
			allowHosts=new ArrayList<String>();
			allowHosts.addAll(Arrays.asList(allowHost.split(",")));
		}
		String appCookie=getEnvironments(APP_COOKIES);
		if(appCookie!=null) {
			appCookies=new ArrayList<String>();
			for(String s:appCookie.split(",")){
				LOGGER.info("App Cookie{}"+s);
			    appCookies.add(s);
			}
		}
		/*Http Methods*/
		if(methodAllows!=null){
	    	ALLOW_METHODS=new ArrayList<String>();
	    	for(String s:methodAllows.split(",")){
	    		ALLOW_METHODS.add(s);
	    	}
	    }
		allowContextPath=config.getInitParameter(ALLOW_CONTEXT_PATH);
		if(allowContextPath==null || (allowContextPath!=null && allowContextPath.length()==0)){
		    allowContextPath=getEnvironments(ALLOW_CONTEXT_PATH);
		}
	}
	
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,FilterChain filterChain)
			throws IOException, ServletException {
		 String errorMsg=null;
		 HttpServletRequest request=(HttpServletRequest)servletRequest;
		 HttpServletResponse response=(HttpServletResponse)servletResponse;
	     XSSRequestWrapper requestWrapper=new XSSRequestWrapper(request);
	     String requestBody=requestWrapper.getBody();
	     String queryString=requestWrapper.getQueryString();
	     boolean isHeaderAllow=requestWrapper.isHeaderAllowed();
	     LOGGER.info("Request Data::{}"+requestBody);
	     LOGGER.info("Query String::{}"+queryString);
	     LOGGER.info("Header Data::{}"+isHeaderAllow);
	     setSSLCookies(requestWrapper,response);
	     String method=requestWrapper.getMethod();
	     boolean isMethodAllow=hasMethodAllowed(method);
	     if(isCrossSiteRequest(requestWrapper) && isMethodAllow){
	    	 if((requestBody!=null && isVulnerability(requestBody) && queryString!=null && isVulnerability(queryString) && isHeaderAllow)|| 
	    			 (requestBody==null && queryString!=null && isVulnerability(queryString) && isHeaderAllow)||
	    			 (requestBody!=null && isVulnerability(requestBody) && queryString==null && isHeaderAllow)||
	    			 (requestBody==null && queryString==null && isHeaderAllow)) {
	    		 filterChain.doFilter(requestWrapper,response);
	    	 }else{
	    		 errorMsg=INVALID_REQUEST;
	    	 }
	     }else {
	    	 errorMsg=ACCESS_DENIDED;
	     }
		if(errorMsg!=null) {
			LOGGER.info("isMethodAllow{}"+isMethodAllow);
			response.setStatus(isMethodAllow?500:400);
			response.sendError(isMethodAllow?HttpServletResponse.SC_BAD_REQUEST:HttpServletResponse.SC_METHOD_NOT_ALLOWED);
			response.setContentType("text/html");
			response.getOutputStream().write(errorMsg.getBytes());
			response.getOutputStream().flush();
			response.getOutputStream().close();
		}
	}
	private boolean hasMethodAllowed(String method){
		  LOGGER.info("****************Method Checking***********************");
		  LOGGER.info("Method{}"+method);
		  Boolean flag=Boolean.FALSE;  
		  if(ALLOW_METHODS!=null && ALLOW_METHODS.contains(method.toUpperCase())){
			  flag=Boolean.TRUE;
		  }else{
			  flag=Boolean.FALSE;
		  }
		  LOGGER.info("After method checking flag{}"+flag); 
		  return flag; 
	}
	public void setSSLCookies(HttpServletRequest request,HttpServletResponse response){
		LOGGER.info("<<<<<<<<<<<Enter into setSSLCookies>>>>>>>>>>>>>>>");
		Cookie []cookies=request.getCookies();
    	if(cookies!=null){
			  for(Cookie cookie:cookies){  
				  if(cookie.getName().equalsIgnoreCase(OBSSO_COOKIE)||cookie.getName().equalsIgnoreCase(SESSION_ID)){                    
					  if(!cookie.getSecure()){
						  cookie.setSecure(true);
						  cookie.setComment(HTTP_ONLY);
						  response.addCookie(cookie);
					  }else if(cookie.getComment()==null || !HTTP_ONLY.equals(cookie.getComment())){
						  cookie.setComment(HTTP_ONLY);
						  response.addCookie(cookie);
					  }
				  }else if(cookie.getName().equalsIgnoreCase(GEAR_COOKIE)||cookie.getName().equalsIgnoreCase(SERVERID_COOKIE)){
					  if(!cookie.getSecure()){
						  cookie.setSecure(true);
						  cookie.setComment(HTTP_ONLY);
						  response.addCookie(cookie);
					   }else if(cookie.getComment()==null || !HTTP_ONLY.equals(cookie.getComment())){
							  cookie.setComment(HTTP_ONLY);
							  response.addCookie(cookie);
					   }
				  }else if(cookie.getName().equalsIgnoreCase(EDOS_LOGIN_COOKIE) || cookie.getName().equalsIgnoreCase(EDOS_AMCV_COOKIE)) {
					  if(!cookie.getSecure()) {
						  cookie.setSecure(true);
						  cookie.setComment(HTTP_ONLY);
						  response.addCookie(cookie); 
					  }else if(cookie.getComment()==null || !HTTP_ONLY.equals(cookie.getComment())){
						  cookie.setComment(HTTP_ONLY);
						  response.addCookie(cookie);
					  }
				  }else if(appCookies!=null && !appCookies.isEmpty()){
					  if(appCookies.contains(cookie.getName()) && !cookie.getSecure()){
						  cookie.setSecure(true);
						  cookie.setComment(HTTP_ONLY);
						  response.addCookie(cookie); 
					  }else if(cookie.getComment()==null || !HTTP_ONLY.equals(cookie.getComment())){
						  cookie.setComment(HTTP_ONLY);
						  response.addCookie(cookie);
					  }
				  }
			  }
		}
    	LOGGER.info("<<<<<<<<<<<End setSSLCookies>>>>>>>>>>>>>>>");	
	}
	
	public boolean isCrossSiteRequest(HttpServletRequest request) {
		LOGGER.info("<<<<<<<<<<<Enter isCrossSiteRequest>>>>>>>>>>>>>>>");
		boolean flag=false;
		String envType=System.getProperty("cisco.life");
    	String referer=request.getHeader("Referer");
    	String host=request.getRemoteHost();
    	String url=request.getRequestURI();
    	String hostUrl=request.getRequestURL().toString();
    	LOGGER.info("Before Referer::{}"+referer+" Request URL::{}"+url+" Host With Request URL::{}"+hostUrl);
    	LOGGER.info("Allowed ContextPath{}"+allowContextPath);
    	if(referer==null){
    	    referer=CISCO_DOMAIN;
    	}
    	LOGGER.info("After Referer::{}"+referer);
        if((referer==null || referer!=null) && envType.equals("local")){
    		referer=CISCO_DOMAIN;
    		hostUrl=CISCO_DOMAIN;
    	}
        if((referer!=null && (referer.contains(CISCO_DOMAIN)||referer.contains(WEBEX_DOMAIN))) 
    			&& (hostUrl!=null && (hostUrl.contains(CISCO_DOMAIN)||hostUrl.contains(WEBEX_DOMAIN)))){
    		flag=true;
    	}if((referer!=null && (referer.contains(CISCO_DOMAIN)||referer.contains(allowContextPath))) &&
    			(allowContextPath!=null && hostUrl!=null && hostUrl.contains(allowContextPath))){
    		LOGGER.info("********Validating Context Path*************");
    		flag=true;
    	}else if(url!=null && url.equals(emanURL)){
    		flag=true;
    	}
        LOGGER.info("<<<<<<<<<<<End isCrossSiteRequest>>>>>>>>>>>>>>>");
        return flag;
	}
	private boolean isVulnerability(String requestData) {
		LOGGER.info("<<<<<<<<<<<Start isVulnerability>>>>>>>>>>>>>>>");
		boolean flag=true;
		LOGGER.info("Request Data{}::"+requestData);
		if(requestData!=null && isSecurityFilter()){
			LOGGER.info("****Started Validate on Body (Or) Query Parameters*****");
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
		LOGGER.info("Is Valid Request Data::{}"+flag);
		LOGGER.info("<<<<<<<<<<<End isVulnerability>>>>>>>>>>>>>>>");
		return flag;
	}
	private boolean isSecurityFilter() {
		LOGGER.info("<<<<<<<<<<<Start isSecurityFilter>>>>>>>>>>>>>>>");
		String isRun=System.getProperty(IS_SECURITY_RUN);
		LOGGER.info("IS_SECURITY_RUN::{}"+isRun);
		if(isRun==null) {
			isRun=System.getenv(IS_SECURITY_RUN);
		}
		LOGGER.info("<<<<<<<<<<<End isSecurityFilter>>>>>>>>>>>>>>>");
		return (isRun!=null && IS_SECURITY_RUN_NO.equals(isRun))?false:true;
	}
	private String getEnvironments(String key){
		String value=System.getProperty(key);
		if(value==null) {
			value=System.getenv(key);
		}
		return value;
	}
	public void destroy() {
		
	}
}