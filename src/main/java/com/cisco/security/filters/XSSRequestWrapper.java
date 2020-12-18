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

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.json.XML;

import com.cisco.security.util.SecurityContants;


public class XSSRequestWrapper extends HttpServletRequestWrapper {

	private final static Logger LOGGER=Logger.getLogger(XSSRequestWrapper.class);
	
	public static final String UTF8 = "UTF-8";
	public final String body;
	public final String queryString;
	public final boolean isHeaderAllowed;
	public final boolean isXmlRequest;
	private final String IS_SQL_QUERY="isSqlQuery";
	
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
		 if((bodyData!=null && bodyData.length()!=0) &&
				 (request!=null && request.getContentType()!=null && request.getContentType().contains("application/soap+xml"))){
			  this.isXmlRequest=true;
		 }else{
			 this.isXmlRequest=false;
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

				@Override
				public boolean isFinished() {
					// TODO Auto-generated method stub
					return false;
				}

				@Override
				public boolean isReady() {
					// TODO Auto-generated method stub
					return false;
				}

				@Override
				public void setReadListener(ReadListener readListener) {
					// TODO Auto-generated method stub
					
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
			if(!param.getKey().equals(IS_SQL_QUERY)){
				query+=param.getKey()+"="+this.getParameter(param.getKey());
				i+=1;
				if(i<entrySet.size()) {
					query+="&";
				}
			}else{
				query=null;
				break;
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
	public boolean isXmlRequest() {
		return isXmlRequest;
	}
	private boolean isVulnerability(String requestData) {
		LOGGER.info("<<<<<<<<<<<Start isVulnerability On Headers>>>>>>>>>>>>>>>");
		LOGGER.info("Header Request Data{}"+requestData);
		boolean flag=true;
		if(requestData!=null){
			LOGGER.info("****Started Validate on Header Data*******");
		    flag=SecurityContants.isVulnerabilityCheckPoint(requestData);
    	}else{
    		flag=true;
    	}
		LOGGER.info("Is Valid Header Data::{}"+flag);
		LOGGER.info("<<<<<<<<<<<End isVulnerability On Headers>>>>>>>>>>>>>>>");
		return flag;
	}
}