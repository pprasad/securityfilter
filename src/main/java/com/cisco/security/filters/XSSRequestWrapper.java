package com.cisco.security.filters;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.log4j.Logger;


public class XSSRequestWrapper extends HttpServletRequestWrapper {

	private final static Logger LOGGER=Logger.getLogger(XSSRequestWrapper.class);
	
	public static final String UTF8 = "UTF-8";
	public final String body;
	public final String queryString;
	public final boolean isHeaderAllowed;
	
	public XSSRequestWrapper(HttpServletRequest request){
		 super(request);
		 StringBuilder bodyData=new StringBuilder();
		 BufferedReader reader=null;
		 String readLine=null;
		 try {
			  InputStream inputStream=request.getInputStream();
			  if(inputStream!=null) {
				  reader=new BufferedReader(new InputStreamReader(inputStream));
				  while((readLine=reader.readLine())!=null) {
					   bodyData.append(readLine);
				  }
			  }
		 }catch(Exception ex) {
			 LOGGER.error("Exception",ex);
		 }finally {
			 if(reader!=null) {
				 try {
					reader.close();
				 }catch(Exception ex) {
					 LOGGER.error("Exception",ex);
				 }
			 }
		 }
	     this.body=bodyData.length()==0?null:bodyData.toString();
	     this.queryString=this.getQueryParameters();
	     this.isHeaderAllowed=this.getHeaders();
	}
	@Override
	public ServletInputStream getInputStream() throws IOException {
		 String data=(body!=null)?body:"";
		 final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(data.getBytes());
	        ServletInputStream servletInputStream = new ServletInputStream() {
	            public int read() throws IOException {
	                return byteArrayInputStream.read();
	            }
	        };
	        return servletInputStream;
	}
	@Override
	public BufferedReader getReader() throws IOException {
		return new BufferedReader(new InputStreamReader(this.getInputStream()));
	}
	private String getQueryParameters() {
		LOGGER.info("****************Start getQueryParameters****************");
		String query=null;
		Set<Map.Entry<String,Object>> entrySet=this.getParameterMap().entrySet();
		int i=0;
		for(Map.Entry<String,Object> param:entrySet) {
			if(query==null) {query="";}
		    query+=param.getKey()+"="+this.getParameter(param.getKey());
			i+=1;
			if(i<entrySet.size()) {
				query+="&";
			}
		}
		LOGGER.info("****************END getQueryParameters****************");
		return query;
	}
	private boolean getHeaders(){
		boolean flag=true;
		Enumeration<String> headers=this.getHeaderNames();
		while(headers.hasMoreElements()){
			String key=headers.nextElement();
			if(!"cookie".equalsIgnoreCase(key) && !"accept".equalsIgnoreCase(key)){
				String header=key+"="+this.getHeader(key);
				flag=isVulnerability(header);
				if(!flag){
					break;
				}
			}
		}
		return flag;
	}
	public String getBody() {
		return this.body;
	}
	public String getQueryString() {
		return queryString;
	}
	public boolean isHeaderAllowed() {
		return isHeaderAllowed;
	}
	private boolean isVulnerability(String requestData) {
		LOGGER.info("<<<<<<<<<<<Start isVulnerability On Headers>>>>>>>>>>>>>>>");
		LOGGER.info("Header Request Data{}"+requestData);
		boolean flag=true;
		if(requestData!=null){
			LOGGER.info("****Started Validate on Header Data*******");
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
		LOGGER.info("Is Valid Header Data::{}"+flag);
		LOGGER.info("<<<<<<<<<<<End isVulnerability On Headers>>>>>>>>>>>>>>>");
		return flag;
	}
}