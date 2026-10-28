import {initializeApp} from 'https://www.gstatic.com/firebasejs/13.1.0/firebase-app.js';
import {initializeAuth,inMemoryPersistence,browserPopupRedirectResolver,GoogleAuthProvider,signInWithPopup,onAuthStateChanged,signOut} from 'https://www.gstatic.com/firebasejs/13.1.0/firebase-auth.js';
import {firebaseConfig} from './firebase-config.mjs';
export function createAuth(){
 if(!firebaseConfig||typeof firebaseConfig.projectId!=='string'||!firebaseConfig.apiKey||!firebaseConfig.authDomain||!firebaseConfig.appId)throw Error('Firebase is not configured');
 const app=initializeApp(firebaseConfig);
 const auth=initializeAuth(app,{persistence:inMemoryPersistence,popupRedirectResolver:browserPopupRedirectResolver});
 const provider=new GoogleAuthProvider();provider.setCustomParameters({prompt:'select_account'});
 return {app,auth,login:()=>signInWithPopup(auth,provider),logout:()=>signOut(auth),onUser:callback=>onAuthStateChanged(auth,user=>callback(user?{uid:user.uid}:null))};
}
