/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2009 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 */

/*
 * author Javed Shah
 * 
 */

package org.forgerock.openam.authentication.modules.impersonation;

import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.shared.debug.Debug;
import com.iplanet.sso.SSOException;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.servlet.http.Cookie;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;

import org.apache.http.HttpEntity;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import javax.ws.rs.core.HttpHeaders;

import java.util.Map;

import org.json.simple.parser.JSONParser;
import org.json.simple.JSONObject;

public class ImpersonationModule extends AMLoginModule {

    private static final String AUTH_MODULE_NAME = "amAuthImpersonation";
    
    private static final Debug debug = Debug.getInstance(AUTH_MODULE_NAME);
    // orders defined in the callbacks file
    private String userResponse;
    protected String validatedUserID;
    private String userName;
    private Subject subject = null;
    private String groupName;
    private String question;
    private String resourceSet;
    
    private String policyRealm;
    private String authnRealm;
    private String policySet;
    private String checkGroupMembership;
    private String openamServer;
    
    private Map options;
    private ResourceBundle bundle;
    public Map currentConfig;
    private Map sharedState;
    private String currentConfigName;
    // Name of the resource bundle
    private final static String amAuthImpersonation = "amAuthImpersonation";
    private static final String AUTHLEVEL = "iplanet-am-auth-impersonation-auth-level";
    private static final String ATTR_NAME = "iplanet-am-auth-impersonation-group-name";
    private static final String IMPERSONATION_ID_STRING = "iplanet-am-auth-impersonation-id";
    private static final String RESOURCE_SET = "iplanet-am-auth-resource-set";
    private static final String POLICY_REALM = "iplanet-am-auth-policy-realm";
    private static final String AUTHN_REALM = "iplanet-am-auth-authentication-realm";
    private static final String POLICY_SET = "iplanet-am-auth-policy-set-name";
    private static final String CHECK_GROUP_MEMBERSHIP = "iplanet-am-auth-check-group-membership";
    private static final String OPENAM_SERVER = "iplanet-am-auth-openam-server";
    
    /**
     * Constructs an instance of the ChallengeResponseModule.
     */
    public ImpersonationModule() {
    	super();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(Subject subject, Map sharedState, Map options) {
    	String authLevel = CollectionHelper.getMapAttr(options, AUTHLEVEL);

        if (authLevel != null) {
            try {
                setAuthLevel(Integer.parseInt(authLevel));
            } catch (Exception e) {
                debug.error("Unable to set auth level " + authLevel, e);
            }
        }
        currentConfig = options;
        currentConfigName = 
            (String)options.get(ISAuthConstants.MODULE_INSTANCE_NAME);
        try {
            userName = (String) sharedState.get(getUserKey());
        } catch (Exception e) {
            debug.error("Adaptive.init() : " + "Unable to set userName : ", e);
        }
    	this.options = options;
    	initParams();
    	
    	System.out.println("username -> "+userName);
        System.out.println("sharedState -> "+sharedState);
        System.out.println("options -> "+options);
        
        this.sharedState = sharedState;
        this.subject = subject;
        		
        bundle = amCache.getResBundle(amAuthImpersonation, getLoginLocale());
    }
    
    private void initParams() {
    	groupName = getOption(options, ATTR_NAME);
    	System.out.println("attr -> "+groupName);
    	
    	question = getOption(options, IMPERSONATION_ID_STRING);
    	System.out.println("q -> "+question);
    	
    	resourceSet = getOption(options, RESOURCE_SET);
    	System.out.println("resourceSet -> "+resourceSet);
    	
    	policyRealm = getOption(options, POLICY_REALM);
    	System.out.println("policyRealm -> "+policyRealm);
    	
    	authnRealm = getOption(options, AUTHN_REALM);
    	System.out.println("authnRealm -> "+authnRealm);
    	
    	policySet = getOption(options, POLICY_SET);
    	System.out.println("policySet -> "+policySet);
    	
    	checkGroupMembership = getOption(options, CHECK_GROUP_MEMBERSHIP);
    	System.out.println("checkGroupMembership -> "+checkGroupMembership);
    	
    	openamServer = getOption(options, OPENAM_SERVER);
    	System.out.println("openamServer -> "+openamServer);
    	
    	
    }
    protected String getOption(Map m, String i) {
    	return CollectionHelper.getMapAttr(m, i);
    }
    protected boolean getOptionAsBoolean(Map m, String i) {
        String s = null;
        s = CollectionHelper.getMapAttr(m, i);
        return Boolean.parseBoolean(s);
    }

    protected int getOptionAsInteger(Map m, String i) {
        String s = null;
        int retVal = 0;

        s = CollectionHelper.getMapAttr(m, i);
        if (s != null) {
            retVal = Integer.parseInt(s);
        }
        return retVal;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int process(Callback[] callbacks, int state) throws LoginException {
    	
    	System.out.println("INSIDE process of ImpersonationModule, state: "+state);
    			
    	if (debug.messageEnabled()) {
    		debug.message("ImpersonationModule::process state: " + state);
        }
    	int nextState = ISAuthConstants.LOGIN_SUCCEED;
        switch (state) {
         case 4:
        	 System.out.println("state 4");
        	 // error condition, show page
        	 throw new AuthLoginException("Incorrect authorization!");
         case 1:
        	 substituteUIStrings();
        	 //nextState = ISAuthConstants.LOGIN_SUCCEED;
        	 nextState = 2;
        	 break;
         case 3:
        	 userName = ( (NameCallback) callbacks[0]).getName();
             String userPassword = String.valueOf(((PasswordCallback)
                 callbacks[1]).getPassword());
             if (userPassword == null || userPassword.length() == 0) {
                 if (debug.messageEnabled()) {
                     debug.message("Impersonation.process: Password is null/empty");
                 } 
                 throw new InvalidPasswordException("amAuth",
                         "invalidPasswd", null);
             }
             //store username password both in success and failure case
             storeUsernamePasswd(userName, userPassword);
             
             AMIdentityRepository idrepo = getAMIdentityRepository(
                 getRequestOrg());
             Callback[] idCallbacks = new Callback[2];
             try {
	             idCallbacks = callbacks;
	             boolean success = idrepo.authenticate(idCallbacks);
	             // proceed if admin authenticated
	             if (success) {
 				
				
	            	validatedUserID = null;
	            	// 1. Search for group membership
	            	if(checkGroupMembership.equalsIgnoreCase("true")) {
	            		
	            	
			        	AMIdentity amIdentity = getGroupIdentity(groupName);
				        Set<String> attr = (Set<String>) amIdentity.getAttribute("uniqueMember"); 
				        Iterator<String> i = attr.iterator();
						// check if sign on user is memberof group 
				        while (i.hasNext()) {
							try {
								String member = (String) i.next();
								System.out.println("value of attribute: "+member);
								// check previously authenticated user is a memberof
								userName = (String) sharedState.get(getUserKey());
								System.out.println("userName to check: "+userName);
								if(member.indexOf(userName)!= -1) {
									System.out.println("match found! admin: "+userName+" allowed to impersonate user: "+userResponse);
									
									// for sanity, ensure the supplied userid is a valid one
									try {
										validatedUserID = userResponse; // create session for the userid provided by admin 
										AMIdentity impersonatedId = getIdentity(validatedUserID);
										// optionally, we default to LOGIN_SUCCEED
										//nextState = ISAuthConstants.LOGIN_SUCCEED;
										
									} catch(Exception ex) {
										System.out.println("Exception thrown validating impersonated userid " + ex);
										throw new AuthLoginException("EImpersonationModule: Exception thrown validating impersonated userid");
									}
									break;
								}
							} catch (Exception e) {
								System.out.println("Cannot parse json. " + e);
								throw new AuthLoginException("Cannot parse json..unable to read attribtue value using amIdentity");
							}
				        }
				        if(checkGroupMembership.equalsIgnoreCase("true") && validatedUserID == null) {
				        	// Admin was not authorized to impersonate other users
				        	nextState = 4;
				        	throw new AuthLoginException("Admin was not authorized to impersonate other users");
				        }
	            	}
			        
			        // 2. Check for policy evaluation
			        // get the ssoToken first, for use with the REST call
	        	 	String url = openamServer+"/json/"+authnRealm+"/authenticate";
			        HttpClient httpClient = HttpClientBuilder.create().build();
		    		HttpPost postRequest = new HttpPost(url); 
		    		String cookie = "";
			        try {
			        	
			        	System.out.println("BEFORE policy1 eval...");
			        	
			    		
			    		postRequest.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
			    		
			    		// TBD: replace with admin provided username and password- stick this code into the impersonate auth module
			    		postRequest.setHeader("X-OpenAM-Username", userName);
			    		postRequest.setHeader("X-OpenAM-Password", userPassword);
				        
				        
			    		StringEntity input = new StringEntity("{}");
			    		input.setContentType("application/json");
			    		postRequest.setEntity(input);

			    		HttpResponse response = httpClient.execute(postRequest);

			    		 String json = EntityUtils.toString(response.getEntity(), "UTF-8");
			    		 System.out.println("json/"+authnRealm+"/authenticate response-> "+json);
			             try {
			                 JSONParser parser = new JSONParser();
			                 Object resultObject = parser.parse(json);

			                 if (resultObject instanceof JSONArray) {
			                     JSONArray array=(JSONArray)resultObject;
			                     for (Object object : array) {
			                         JSONObject obj =(JSONObject)object;
			                         System.out.println("jsonarray-> "+obj);
			                     }

			                 }else if (resultObject instanceof JSONObject) {
			                     JSONObject obj =(JSONObject)resultObject;
			                     System.out.println("tokenId-> "+obj.get("tokenId"));
			                     cookie = (String) obj.get("tokenId");
			                 }

			             } catch (Exception e) {
			                 // TODO: handle exception
			            	 nextState = 4;
			             }
			             System.out.println("AFTER policy1 eval...");
			            // Headers
			            org.apache.http.Header[] headers = response.getAllHeaders();
			            for (int j = 0; j < headers.length; j++) {
			                System.out.println(headers[j]);
			            }

			       
			        } catch (Exception e) {
			          System.err.println("Fatal  error: " + e.getMessage());
			          e.printStackTrace();
			          nextState = 4;
			        } 
			        
			        System.out.println("BEFORE policy2 eval...");
	        	 
	        	 
			        /*Cookie[] cookies = getHttpServletRequest().getCookies();
			        
			        
			        if (cookies != null) {
			          for (int m = 0; m < cookies.length; m++) {
			        	  System.out.println(cookies[m].getName() +":"+cookies[m].getValue());
			            if (cookies[m].getName().equalsIgnoreCase("iPlanetDirectoryPro")) {
			              cookie = cookies[m].getValue();
			              break;
			            }
			          }
			        }*/
			        url = openamServer+"/json/"+policyRealm+"/policies?_action=evaluate";
			        //httpClient = HttpClientBuilder.create().build();
		    		postRequest = new HttpPost(url); 
			        try {
			        	
			    		
			    		postRequest.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
			    		postRequest.setHeader("iPlanetDirectoryPro", cookie);
				        
				        
			    		StringEntity input = new StringEntity("{\"resources\": [\""+new URL(resourceSet)+"\"],\"application\":\""+policySet+"\", \"subject\": {\"ssoToken\":\"" +cookie+"\"}}");
			    		
			    		System.out.println("stringentity-> "+getStringFromInputStream(input.getContent()));
			    		input.setContentType("application/json");
			    		postRequest.setEntity(input);

			    		HttpResponse response = httpClient.execute(postRequest);

			    		 String json = EntityUtils.toString(response.getEntity(), "UTF-8");
			    		 System.out.println("json/"+policyRealm+"/policies?_action=evaluate response-> "+json);
			             try {
			                 JSONParser parser = new JSONParser();
			                 Object resultObject = parser.parse(json);

			                 if (resultObject instanceof JSONArray) {
			                     JSONArray array=(JSONArray)resultObject;
			                     for (Object object : array) {
			                         JSONObject obj =(JSONObject)object;
			                         System.out.println("jsonarray-> "+obj);
			                         
			 // stringentity-> {"resources": ["http://ec2-54-67-72-146.us-west-1.compute.amazonaws.com:8080/openam"],"application":"iPlanetAMWebAgentService", "subject": {"ssoToken":"AQIC5wM2LY4SfcyO_yXJfVhQKl0V8Up-WpSq3gBjV8oLBQs.*AAJTSQACMDEAAlNLABQtNTQ0NjAyOTU0NDM3OTA2NjgxNg..*"}}
			 //json/policies?_action=evaluate response-> [{"advices":{},"actions":{"POST":true,"GET":true},"resource":"http://ec2-54-67-72-146.us-west-1.compute.amazonaws.com:8080/openam","attributes":{"cn":["Javed Shah"],"xx":["yy"]}}]
			 // jsonarray-> {"resource":"http:\/\/ec2-54-67-72-146.us-west-1.compute.amazonaws.com:8080\/openam","attributes":{"cn":["Javed Shah"],"xx":["yy"]},"advices":{},"actions":{"POST":true,"GET":true}}
			                         		
			                         JSONObject actions = (JSONObject) obj.get("actions");
			                         Boolean actionGet = (Boolean) actions.get("GET");
			                         Boolean actionPost = (Boolean) actions.get("POST");
			                         System.out.println("actionGet : "+actionGet);
			                         System.out.println("actionPost : "+actionPost);
			                         
			                         if(actionGet!=null && actionGet.equals(true) && 
			                        		 actionPost!=null && actionPost.equals(true) ) {
			                        	 nextState = ISAuthConstants.LOGIN_SUCCEED;
			                         } else {
			                        	 System.out.println("actionget and actionpost are not true");
			                        	 nextState = 4;
			                         }
			                     }

			                 } else {
			                     // something went wrong!
			                	 System.out.println("resultObject is not a JSONArray");
			                     nextState = 4;
			                 }

			             } catch (Exception e) {
			                 // TODO: handle exception
			            	 nextState = 4;
			            	 System.out.println("exception invoking json parsing routine");
			            	 e.printStackTrace();
			             }
			             System.out.println("AFTER policy2 eval...");
			            // Headers
			            org.apache.http.Header[] headers = response.getAllHeaders();
			            for (int j = 0; j < headers.length; j++) {
			                System.out.println(headers[j]);
			            }
			            
			            // logout the administrator
			            url = openamServer+"/json/"+authnRealm+"/sessions/?_action=logout";
			            System.out.println("destroying admin session: "+url);
			            postRequest = new HttpPost(url); 
				        try {
				        	postRequest.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
				    		postRequest.setHeader("iPlanetDirectoryPro", cookie);
					        response = httpClient.execute(postRequest);
					        try {
					        	JSONParser parser = new JSONParser();
					        	Object resultObject = parser.parse(json);
					        	if (resultObject instanceof JSONArray) {
				                     JSONArray array=(JSONArray)resultObject;
				                     for (Object object : array) {
				                         JSONObject obj =(JSONObject)object;
				                         System.out.println("logout response-array-> "+obj);
				                     }
					        	} else {
					        		JSONObject obj=(JSONObject) resultObject;
					        	     System.out.println("logout response-> "+obj);
					        	}
					        } catch(Exception e) {
					        	System.out.println("unable to read logout json response");
					        	e.printStackTrace();
					        }
					        
				        } catch(Exception e) {
				        	System.out.println("Issue destroying administrator's session, still proceeding with impersonation");
				        	e.printStackTrace();
				        	
				        }

			       
			        } catch (Exception e) {
			          System.err.println("Fatal  error: " + e.getMessage());
			          e.printStackTrace();
			          nextState = 4;
			        }  
			        
			     // else of admin successful login   
	             } else {
	            	 System.out.println("username:password read from callback: "+userName+" : "+userPassword);
	            	 nextState = 4;
	                 throw new AuthLoginException(amAuthImpersonation, "authFailed",
	                     null);
	             }
	        } catch(com.sun.identity.idm.IdRepoException idrepox) {
	        	System.out.println("IdRepoException thrown " + idrepox);
	        	nextState = 4;
				throw new AuthLoginException("IdRepoException thrown from Impersonation module");
	        } catch(SSOException ssoe) {
	        	System.out.println("SSOException thrown " + ssoe);
	        	nextState = 4;
				throw new AuthLoginException("SSOException thrown from ImpersonationModule module");
	        }
                 
             
				
        	 break;
         case 2:
        	 javax.security.auth.callback.NameCallback response = (javax.security.auth.callback.NameCallback) callbacks[0];
        	 userResponse = new String(response.getName());
             // check the response against OpenDJ
    		 System.out.println("user to impersonate : state 2: "+userResponse);
    		 
			 nextState = 3;
		        
             break;
         default:
             throw new AuthLoginException("invalid state");
  
         }
         return nextState;
    }
    /**
     * Gets the user's AMIdentity from LDAP.
     *
     * @param userName The user's name.
     * @return The AMIdentity for the user.
     */
    public AMIdentity getIdentity(String userName) {
        AMIdentity amIdentity = null;
        AMIdentityRepository amIdRepo = getAMIdentityRepository(getRequestOrg());

        IdSearchControl idsc = new IdSearchControl();
        idsc.setAllReturnAttributes(true);
        Set<AMIdentity> results = Collections.EMPTY_SET;

        try {
            idsc.setMaxResults(0);
            IdSearchResults searchResults = amIdRepo.searchIdentities(IdType.USER, userName, idsc);
            if (searchResults != null) {
                results = searchResults.getSearchResults();
                System.out.println("results: "+results);
            }

            if (results.isEmpty()) {
                throw new IdRepoException("getIdentity : User " + userName
                        + " is not found");
            } else if (results.size() > 1) {
                throw new IdRepoException(
                        "getIdentity : More than one user found for the userName "
                                + userName);
            }

            amIdentity = results.iterator().next();
        } catch (IdRepoException e) {
            debug.error("Error searching Identities with username : " + userName, e);
        } catch (SSOException e) {
            debug.error("Module exception : ", e);
        }

        return amIdentity;
    }
    
    /**
     * Gets the group's AMIdentity from LDAP.
     *
     * @param groupName The group name.
     * @return The AMIdentity for the group.
     */
    public AMIdentity getGroupIdentity(String groupName) {
        AMIdentity amIdentity = null;
        AMIdentityRepository amIdRepo = getAMIdentityRepository(getRequestOrg());

        IdSearchControl idsc = new IdSearchControl();
        idsc.setAllReturnAttributes(true);
        Set<AMIdentity> results = Collections.EMPTY_SET;

        try {
            idsc.setMaxResults(0);
            IdSearchResults searchResults = amIdRepo.searchIdentities(IdType.GROUP, groupName, idsc);
            if (searchResults != null) {
                results = searchResults.getSearchResults();
                System.out.println("results: "+results);
            }

            if (results.isEmpty()) {
                throw new IdRepoException("getIdentity : group " + groupName
                        + " is not found");
            } else if (results.size() > 1) {
                throw new IdRepoException(
                        "getIdentity : More than one result found for the groupName "
                                + groupName);
            }

            amIdentity = results.iterator().next();
        } catch (IdRepoException e) {
            debug.error("Error searching Identities with groupName : " + groupName, e);
        } catch (SSOException e) {
            debug.error("Module exception : ", e);
        }

        return amIdentity;
    }
    // convert InputStream to String
 	private static String getStringFromInputStream(InputStream is) {

 		BufferedReader br = null;
 		StringBuilder sb = new StringBuilder();

 		String line;
 		try {

 			br = new BufferedReader(new InputStreamReader(is));
 			while ((line = br.readLine()) != null) {
 				sb.append(line);
 			}

 		} catch (IOException e) {
 			e.printStackTrace();
 		} finally {
 			if (br != null) {
 				try {
 					br.close();
 				} catch (IOException e) {
 					e.printStackTrace();
 				}
 			}
 		}

 		return sb.toString();

 	}
    
    /**
     * {@inheritDoc}
     */
    @Override
    public Principal getPrincipal() {
        return new ImpersonationModulePrincipal(validatedUserID);
    }
    private void substituteUIStrings() throws AuthLoginException
    {
        // Get service specific attribute configured in OpenAM
        System.out.println("question from config: "+question);

        Callback[] crquestion = getCallback(2);

        replaceCallback(2, 0, new NameCallback(question));
    }

}
