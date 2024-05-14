/*
cron: 50 8 * * *
const $ = new Env("天冀云盘签到");
*/
//https://github.com/wes-lin/Cloud189Checkin/blob/main/src/app.js#L162
const axios = require('axios');
const qs = require('qs');
const crypto = require("crypto");
const JSEncrypt = require('node-jsencrypt');
const notify = require('./sendNotify');
const qlapi = require('./tol_qlapi');
const config = {
  clientId: '538135150693412',
  model: 'KB2000',
  version: '9.0.6',
  pubKey: 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZLyV4gHNDUGJMZoOcYauxmNEsKrc0TlLeBEVVIIQNzG4WqjimceOj5R9ETwDeeSN3yejAKLGHgx83lyy2wBjvnbfm/nLObyWwQD/09CmpZdxoFYCH6rdDjRpwZOZ2nXSZpgkZXoOBkfNXNxnN74aXtho2dqBynTw3NFTWyQl8BQIDAQAB',
}
const headers = {
  'User-Agent': `Mozilla/5.0 (Linux; U; Android 11; ${config.model} Build/RP1A.201005.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/${config.version} Android/30 clientId/${config.clientId} clientModel/${config.model} clientChannelId/qq proVersion/1.0.6`,
  'Referer': 'https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1',
  'Accept-Encoding': 'gzip, deflate',
};

async function doLogin(uname, passwd) {
  try {
    let resp = await axios.post('https://open.e.189.cn/api/logbox/config/encryptConf.do?appId=cloud');
    let pubKey = resp.data.data.pubKey;
    resp = await axios.get('https://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https://cloud.189.cn/web/redirect.html?returnURL=/main.action');
    //获取最后请求url中的参数reqId和lt
    let Reqid = resp.request.path.match(/reqId=(\w+)/)[1];
    let Lt = resp.request.path.match(/lt=(\w+)/)[1];
    let tHeaders = {
      "Content-Type": "application/x-www-form-urlencoded",
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
      'Referer': 'https://open.e.189.cn/', Lt, Reqid,
    };
    let data = { version: '2.0', appKey: 'cloud' };
    resp = await axios.post('https://open.e.189.cn/api/logbox/oauth2/appConf.do', qs.stringify(data), { headers: tHeaders });
    let returnUrl = resp.data.data.returnUrl;
    let paramId = resp.data.data.paramId;
    const keyData = `-----BEGIN PUBLIC KEY-----\n${pubKey}\n-----END PUBLIC KEY-----`;
    const jsencrypt = new JSEncrypt();
    jsencrypt.setPublicKey(keyData);
    const enUname = Buffer.from(jsencrypt.encrypt(uname), 'base64').toString('hex');
    const enPasswd = Buffer.from(jsencrypt.encrypt(passwd), 'base64').toString('hex');
    data = {
      appKey: 'cloud',
      version: '2.0',
      accountType: '01',
      mailSuffix: '@189.cn',
      validateCode: '',
      returnUrl,
      paramId,
      captchaToken: '',
      dynamicCheck: 'FALSE',
      clientType: '1',
      cb_SaveName: '0',
      isOauth2: false,
      userName: `{NRP}${enUname}`,
      password: `{NRP}${enPasswd}`,
    };
    resp = await axios.post('https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do', qs.stringify(data), { headers: tHeaders, validateStatus: null });
    if (resp.data.toUrl) { 
      let cookies = resp.headers['set-cookie'].join(';');
      resp = await axios.get(resp.data.toUrl, { headers: { ...headers, Cookie: cookies }, maxRedirects: 0, validateStatus: null });
      cookies += '; ' + resp.headers['set-cookie'].join(';');
      return cookies;
    }
    console.log('doLogin: ', resp.data);
  } catch (error) {
  }
  return null;
}

function getSignature(data) { 
  const e = Object.entries(data).map((t) => t.join("="));
  e.sort((a, b) => (a > b ? 1 : a < b ? -1 : 0));
  return crypto.createHash("md5").update(e.join("&")).digest("hex");
}

async function familyCheckin(cookies) { 
  const ckRes = []
  try {
    let resp = await axios.get('https://cloud.189.cn/api/portal/v2/getUserBriefInfo.action', { headers: { ...headers, Cookie: cookies }, validateStatus: null });
    let { sessionKey } = resp.data;
    let time = String(Date.now());
    let signature = getSignature({ sessionKey, Timestamp: time, AppKey: '600100422' });
    let sHeader = { "Sign-Type": "1", Signature: signature, Timestamp: time, Appkey: '600100422' };
    resp = await axios.get(`https://cloud.189.cn/api/open/oauth2/getAccessTokenBySsKey.action?sessionKey=${sessionKey}`, { headers: { ...sHeader, Cookie: cookies }, validateStatus: null });
    let { accessToken } = resp.data;
    //getFamilyList
    time = String(Date.now());
    signature = getSignature({ AccessToken: accessToken, Timestamp: time });
    sHeader = { "Sign-Type": "1", Signature: signature, Timestamp: time, Accesstoken: accessToken, Accept: "application/json;charset=UTF-8" };
    resp = await axios.get('https://api.cloud.189.cn/open/family/manage/getFamilyList.action', { headers: { ...sHeader, Cookie: cookies }, validateStatus: null });
    let familyIds = resp.data.familyInfoResp.map(item => item.familyId);
    for await (const familyId of familyIds) {
      time = String(Date.now());
      signature = getSignature({ familyId, AccessToken: accessToken, Timestamp: time });
      sHeader = { "Sign-Type": "1", Signature: signature, Timestamp: time, Accesstoken: accessToken, Accept: "application/json;charset=UTF-8" };
      resp = await axios.get(`https://api.cloud.189.cn/open/family/manage/exeFamilyUserSign.action?familyId=${familyId}`, { headers: { ...sHeader, Cookie: cookies }, validateStatus: null });
      // console.log('familyCheckin: ', resp.data);
      ckRes.push('家庭任务' + `${resp.data.signStatus ? "已经签到过了，" : ""}签到获得${ resp.data.bonusSpace }M空间`);
    }
  } catch (error) {
    console.log('familyCheckin: ', error);
    ckRes.push('家庭任务异常');
  }
  return ckRes;
}

async function doCheckin(cookies) { 
  let tasks = [
    `https://cloud.189.cn/mkt/userSign.action?rand=${new Date().getTime()}&clientType=TELEANDROID&version=${config.version}&model=${config.model}`,
    'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN',
    'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN',
    'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_2022_FLDFS_KJ&activityId=ACT_SIGNIN',
  ];
  const ckRes = []
  let index = 0;
  for (const task of tasks) {
    try {
      let resp = await axios.get(task, { headers: { ...headers, Cookie: cookies }, validateStatus: null });
      console.log(task, resp.data);
      if (index === 0) { 
        ckRes.push(`${resp.data.isSign ? '已经签到过了，' : ''}签到获得${resp.data.netdiskBonus}M空间`);
      }else if (resp.data.errorCode === 'User_Not_Chance') {
        ckRes.push(`第${index}次抽奖失败,次数不足`);
      } else {
        ckRes.push(`第${index}次抽奖成功,抽奖获得${resp.data.prizeName}`);
      }
    } catch (error) {
      ckRes.push(`第${index}签到失败`);
    }
    index++;
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }
  return ckRes;
}

async function getSizeInfo(cookies) { 
  let message = [];
  try {
    let resp = await axios.get('https://cloud.189.cn/api/portal/getUserSizeInfo.action', { headers: { ...headers, Cookie: cookies, Accept: "application/json;charset=UTF-8" }, validateStatus: null });
    let { cloudCapacityInfo, familyCapacityInfo } = resp.data;
    let totalSize = (cloudCapacityInfo.totalSize / 1024 / 1024 / 1024).toFixed(2);
    let usedSize = (cloudCapacityInfo.usedSize / 1024 / 1024 / 1024).toFixed(2);
    let freeSize = (cloudCapacityInfo.freeSize / 1024 / 1024 / 1024).toFixed(2);
    message.push(`个人总容量${totalSize}G, 已使用${usedSize}G, 可用${freeSize}G`);
    totalSize = (familyCapacityInfo.totalSize / 1024 / 1024 / 1024).toFixed(2);
    usedSize = (familyCapacityInfo.usedSize / 1024 / 1024 / 1024).toFixed(2);
    freeSize = (familyCapacityInfo.freeSize / 1024 / 1024 / 1024).toFixed(2);
    message.push(`家庭总容量${totalSize}G, 已使用${usedSize}G, 可用${freeSize}G`);
  } catch (error) {
    console.log('getSizeInfo error: ', error);
    message.push('获取用户容量异常');
  }
  return message;
}

!(async () => { 
  const c189s = await qlapi.getQLEnvs('CLOUD_189');
  // const c189s = { data: [{ value: '123456&123@112' }] };
  if (!c189s || !c189s.data || !c189s.data.length) {
    console.log('未获取到天冀云盘 CLOUD_189');
    return;
  }
  const message = []
  let index = 1;
  for (const c189 of c189s.data) {
    //uname passwd从c189中获取
    let uname = c189.value.split('&')[0];
    let passwd = c189.value.split('&')[1];
    console.log(`开始签到第${index}个账号,${uname}`);
    let cookies = await doLogin(uname, passwd);
    if (cookies) {
      message.push(`账号${index}-${uname}`);
      let ckMsgs = await doCheckin(cookies);
      message.push(...ckMsgs);
      let fmlyMsgs = await familyCheckin(cookies);
      message.push(...fmlyMsgs);
      let sizeMsgs = await getSizeInfo(cookies);
      message.push(...sizeMsgs);
    }else{
      message.push(`账号${index}-${uname}登录失败`);
    }
    index++;
    message.push('------------------------\n');
  };
  console.log(message.join('\n'));
  await notify.sendNotify(`天冀云盘签到`, message.join('\n'))
})();
