import pickle5 as pickle
import pandas as pd
import lightgbm
from get_features import generate_data_set

def predict(url):
  ######################################################
  feature = generate_data_set(url)
  df=pd.DataFrame(feature,columns=['having_IP_Address','URL_Length','Shortining_Service', 'having_At_Symbol' , 'double_slash_redirecting', 'Prefix_Suffix' , 'having_Sub_Domain',  'SSLfinal_State', 'Domain_registeration_length','Favicon', 'port' , 'HTTPS_token' , 'Request_URL' , 'URL_of_Anchor',  'Links_in_tags', 'SFH' , 'Submitting_to_email' ,  'Abnormal_URL', 'Redirect' , 'on_mouseover' ,  'RightClick' , 'popUpWidnow' ,  'Iframe' , 'age_of_domain' , 'DNSRecord' , 'web_traffic' , 'Page_Rank',  'Google_Index' ,  'Links_pointing_to_page', 'Statistical_report'])
  ############################################################
  temp=pd.DataFrame()
  temp["Rule Based Phishing"]=df['having_IP_Address']*0.05 +df['URL_Length']*0.025 +df['Shortining_Service']*0.025+ df['having_At_Symbol']*0.025 + df['double_slash_redirecting']*0.025+ df['Prefix_Suffix']*0.025 + df['having_Sub_Domain']*0.05+  df['SSLfinal_State']*0.025+ df['Domain_registeration_length']*0.025+df['Favicon']*0.025+ df['port']*0.025 + df['HTTPS_token']*0.05 + df['Request_URL']*0.025 + df['URL_of_Anchor']*0.05+  df['Links_in_tags']*0.025+ df['SFH']*0.05 + df['Submitting_to_email']*0.05 +  df['Abnormal_URL']*0.025+ df['Redirect']*0.025 + df['on_mouseover']*0.025 +  df['RightClick']*0.025 + df['popUpWidnow']*0.025 +  df['Iframe']*0.025 + df['age_of_domain']*0.025 + df['DNSRecord']*0.05 + df['web_traffic']*0.05 + df['Page_Rank']*0.05+  df['Google_Index']*0.025 +  df['Links_pointing_to_page']*0.025+ df['Statistical_report']*0.05
  # print(temp)

  # temp["Rule Based Phishing"]=(temp["Rule Based Phishing"]-temp["Rule Based Phishing"].min())/(temp["Rule Based Phishing"].max()-temp["Rule Based Phishing"].min())
  # print(temp)

  temp[temp["Rule Based Phishing"] > 0.65]=1
  temp[temp["Rule Based Phishing"]  <= 0.65]=-1


  temp["Rule Based Phishing"]=temp["Rule Based Phishing"].astype("int")
#################################################################################

  lgb = lightgbm.Booster(model_file='lgb-model.txt')
  lgb_pred=lgb.predict(feature)
  if lgb_pred[0]>0.5:
    lgb_pred[0]=1
  else:
    lgb_pred[0]=-1
  reg = pickle.load(open('./final-model.sav', 'rb'))

##################################################################
  rule_pred=temp["Rule Based Phishing"].values

######################################################################
  y = reg.predict([[lgb_pred[0],rule_pred[0]]])
  print(y[0])

  return {
    "phishing": True if y[0] == 1 else False
  }