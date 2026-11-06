package com.duolink.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.*
import androidx.navigation.compose.*
import coil.compose.AsyncImage

private val Ink = Color(0xFF111318)
private val Gold = Color(0xFFD6B36A)
private val Panel = Color(0xFF20242C)
private val Muted = Color(0xFF9AA3B2)

class MainActivity : ComponentActivity() {
 override fun onCreate(savedInstanceState: Bundle?) {
  super.onCreate(savedInstanceState)
  setContent { DuoLinkApp() }
 }
}

@Composable fun DuoLinkApp() {
 val nav = rememberNavController()
 MaterialTheme(colorScheme = darkColorScheme(primary=Gold, background=Ink, surface=Panel, onBackground=Color.White, onSurface=Color.White)) {
  NavHost(navController=nav, startDestination="home") {
   composable("home") { HomeScreen({nav.navigate("chat")},{nav.navigate("about")},{nav.navigate("settings")}) }
   composable("chat") { ChatScreen { nav.popBackStack() } }
   composable("about") { AboutScreen { nav.popBackStack() } }
   composable("settings") { SettingsScreen { nav.popBackStack() } }
  }
 }
}

@Composable private fun Top(title:String, back:(()->Unit)?=null) {
 Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment=Alignment.CenterVertically) {
  if(back!=null) IconButton(onClick=back){Icon(Icons.Default.ArrowBack,null)}
  else AsyncImage(model=R.drawable.duolink_logo,contentDescription="لوگوی DuoLink",modifier=Modifier.size(42.dp).clip(CircleShape))
  Text(title,Modifier.weight(1f),fontSize=20.sp,fontWeight=FontWeight.Bold,textAlign=TextAlign.Center)
  Spacer(Modifier.width(42.dp))
 }
}

@Composable fun HomeScreen(chat:()->Unit, about:()->Unit, settings:()->Unit) {
 Column(Modifier.fillMaxSize().background(Ink)) {
  Top("DuoLink")
  Column(Modifier.fillMaxSize().padding(20.dp),verticalArrangement=Arrangement.spacedBy(18.dp)) {
   Text("ارتباط خصوصی، برای دو نفر",color=Muted,modifier=Modifier.fillMaxWidth(),textAlign=TextAlign.Center)
   Card(onClick=chat,colors=CardDefaults.cardColors(containerColor=Panel),shape=RoundedCornerShape(24.dp),modifier=Modifier.fillMaxWidth()) {
    Row(Modifier.padding(16.dp),verticalAlignment=Alignment.CenterVertically) {
     AsyncImage(model=R.drawable.nasrin_portrait,contentDescription="عکس مخاطب نسرین خانم",modifier=Modifier.size(76.dp).clip(CircleShape))
     Spacer(Modifier.width(16.dp))
     Column(Modifier.weight(1f)){Text("نسرین خانم",fontSize=20.sp,fontWeight=FontWeight.Bold);Text("مخاطب خصوصی",color=Muted,fontSize=13.sp)}
     Icon(Icons.Default.ChevronRight,null,tint=Gold)
    }
   }
   Tile(Icons.Default.Info,"درباره برنامه",about)
   Tile(Icons.Default.Settings,"تنظیمات",settings)
   Spacer(Modifier.weight(1f))
   Text("DuoLink • نسخه 0.1.0",color=Muted,fontSize=12.sp,modifier=Modifier.fillMaxWidth(),textAlign=TextAlign.Center)
  }
 }
}

@Composable private fun Tile(icon:androidx.compose.ui.graphics.vector.ImageVector,label:String,click:()->Unit) {
 Card(onClick=click,colors=CardDefaults.cardColors(containerColor=Panel),shape=RoundedCornerShape(16.dp),modifier=Modifier.fillMaxWidth()){
  Row(Modifier.padding(17.dp),verticalAlignment=Alignment.CenterVertically){Icon(icon,null,tint=Gold);Spacer(Modifier.width(12.dp));Text(label,Modifier.weight(1f));Icon(Icons.Default.ChevronRight,null,tint=Muted)}
 }
}

@Composable fun AboutScreen(back:()->Unit) {
 Column(Modifier.fillMaxSize().background(Ink)){
  Top("درباره برنامه",back)
  Column(Modifier.fillMaxSize().padding(24.dp),horizontalAlignment=Alignment.CenterHorizontally,verticalArrangement=Arrangement.Center){
   AsyncImage(model=R.drawable.duolink_logo,contentDescription="لوگوی DuoLink",modifier=Modifier.size(132.dp).clip(CircleShape))
   Spacer(Modifier.height(22.dp));Text("DuoLink",fontSize=28.sp,fontWeight=FontWeight.Bold,color=Gold)
   Spacer(Modifier.height(26.dp));Text("نسرین خانم",fontSize=25.sp,fontWeight=FontWeight.Bold,textAlign=TextAlign.Center)
   Spacer(Modifier.height(10.dp));Text("این برنامه مخصوص شما ساخته شده است.",fontSize=18.sp,textAlign=TextAlign.Center,lineHeight=30.sp)
   Spacer(Modifier.height(18.dp));Text("یک ارتباط خصوصی، برای دو نفر",color=Muted,fontSize=14.sp)
   Spacer(Modifier.height(32.dp));Text("نسخه 0.1.0",color=Muted,fontSize=12.sp)
  }
 }
}

private data class Message(val text:String,val mine:Boolean)

@Composable fun ChatScreen(back:()->Unit) {
 var draft by remember { mutableStateOf("") }
 var msgs by remember { mutableStateOf(listOf(Message("سلام نسرین خانم 🌹",true),Message("سلام، وقت شما بخیر",false))) }
 Column(Modifier.fillMaxSize().background(Ink)){
  Row(Modifier.fillMaxWidth().padding(8.dp),verticalAlignment=Alignment.CenterVertically){
   IconButton(onClick=back){Icon(Icons.Default.ArrowBack,null)}
   AsyncImage(model=R.drawable.nasrin_portrait,contentDescription="نسرین خانم",modifier=Modifier.size(44.dp).clip(CircleShape))
   Spacer(Modifier.width(10.dp));Column(Modifier.weight(1f)){Text("نسرین خانم",fontWeight=FontWeight.Bold);Text("پیش‌نمایش محلی",color=Muted,fontSize=11.sp)}
   IconButton(onClick={}){Icon(Icons.Default.Call,"تماس صوتی",tint=Gold)}
   IconButton(onClick={}){Icon(Icons.Default.Videocam,"تماس تصویری",tint=Gold)}
  }
  HorizontalDivider(color=Color(0xFF343A45))
  LazyColumn(Modifier.weight(1f).fillMaxWidth().padding(14.dp),verticalArrangement=Arrangement.spacedBy(10.dp)){
   items(msgs){m->Row(Modifier.fillMaxWidth(),horizontalArrangement=if(m.mine)Arrangement.End else Arrangement.Start){
    Surface(color=if(m.mine)Color(0xFF394333) else Panel,shape=RoundedCornerShape(16.dp)){Text(m.text,Modifier.padding(horizontal=14.dp,vertical=10.dp),color=Color.White)}
   }}
  }
  Row(Modifier.fillMaxWidth().padding(10.dp),verticalAlignment=Alignment.CenterVertically){
   IconButton(onClick={}){Icon(Icons.Default.AttachFile,"پیوست",tint=Gold)}
   OutlinedTextField(value=draft,onValueChange={draft=it},modifier=Modifier.weight(1f),placeholder={Text("پیام بنویسید…")},shape=RoundedCornerShape(24.dp),singleLine=true)
   IconButton(onClick={if(draft.isNotBlank()){msgs=msgs+Message(draft.trim(),true);draft=""}}){Icon(Icons.Default.Send,"ارسال",tint=Gold)}
  }
  Text("این نسخه فقط پیش‌نمایش محلی است؛ پیام اینترنتی هنوز فعال نیست.",color=Muted,fontSize=10.sp,modifier=Modifier.fillMaxWidth().padding(bottom=8.dp),textAlign=TextAlign.Center)
 }
}

@Composable fun SettingsScreen(back:()->Unit) {
 Column(Modifier.fillMaxSize().background(Ink)){
  Top("تنظیمات",back)
  Column(Modifier.padding(20.dp),verticalArrangement=Arrangement.spacedBy(14.dp)){
   Text("حریم خصوصی",color=Gold,fontWeight=FontWeight.Bold)
   Text("قفل برنامه، تأیید هویت دو گوشی و مدیریت کلیدها در مراحل بعدی اضافه می‌شوند.",color=Muted,lineHeight=25.sp)
   HorizontalDivider(color=Color(0xFF343A45))
   Text("ارتباط",color=Gold,fontWeight=FontWeight.Bold)
   Text("ارتباط اینترنتی و تماس‌ها هنوز فعال نیستند. این نسخه فقط پوسته اولیه برنامه است.",color=Muted,lineHeight=25.sp)
  }
 }
}
