using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using MVCtest.Common;
using System.Web.Security;

namespace mvct1.Controllers
{
    public class UserController : Controller
    {
        public xw_OAEntities entity = new xw_OAEntities();
        // GET: User
        public ActionResult Index()
        {
            return View();
        }
       
        //获取验证码
        public ActionResult GetValidateCode()
        {
            ValidateCode vCode = new ValidateCode();
            string code = vCode.CreateValidateCode(5);
            Session["ValidateCode"] = code;
            byte[] bytes = vCode.CreateValidateGraphic(code);
            return File(bytes, @"image/jpeg");
        }

        public ActionResult Login()
        {
            return View();
        }
        /// <summary>
        /// 登录页面的登录按钮事件
        /// </summary>
        /// <param name = "loginuser" ></ param >
        /// < param name="password"></param>
        /// <param name = "loginyzhm" ></ param >
        /// < returns ></ returns >
        [HttpPost]
        public ActionResult Login(string loginuser, string loginpwd, string loginyzhm)
        {
            loginuser = string.IsNullOrEmpty(loginuser) ? "" : loginuser.Trim();
            if (!string.IsNullOrEmpty(loginuser.Trim()) && !string.IsNullOrEmpty(loginpwd))
            {
            
                if (Session["staffID"] == null || Session["staffID"].ToString() == "")
                {
                    var action = Request.UrlReferrer.AbsolutePath;
                    //登陆页面需要验证码判断
                    if (Session["ValidateCode"] == null)
                    {
                        ViewData["Tip"] = "验证码失效";
                        return View();
                    }
                    string yanzhenNumber = Session["ValidateCode"].ToString();
                    if (string.IsNullOrEmpty(loginyzhm))
                    {
                        ViewData["Tip"] = "请输入验证码";
                        return View();
                    }
                    if (loginyzhm != yanzhenNumber)
                    {
                        ViewData["Tip"] = "验证码错误";
                        return View();
                    }
                    staffTable staff = entity.staffTable.FirstOrDefault(a => a.userName == loginuser && a.userState == 1);
                    //string passWord = loginpwd + "xcOA$*";
                    //string passwdMD5 = System.Web.Security.FormsAuthentication.HashPasswordForStoringInConfigFile(passWord, "MD5");
                    string passwdMD5 = pub.Md5Encrypt(loginpwd);
                    if (staff != null)
                    {
                        //  对比密码
                        if (staff.passwd == passwdMD5)
                        {
                            //创建身份验证票证，即转换为“已登录状态”
                            FormsAuthentication.SetAuthCookie(loginuser, false);
                            //存入Session
                            //Session["staffJobnumber"] = staff.staffJobnumber;
                            //Session["staffID"] = staff.id;
                            //Session["departID"] = staff.departID;
                            //Session["postID"] = staff.postID;
                            //Session["guanlifanwei"] = staff.guanlifanwei;

                            Response.Cookies["staffID"].Expires = DateTime.Now.AddHours(-12);
                            Response.Cookies["userName"].Expires = DateTime.Now.AddHours(-12);

                            Response.Cookies["staffID"].Value = staff.staffID.ToString();
                            Response.Cookies["staffID"].Expires = DateTime.Now.AddHours(12);
                            Response.Cookies["userName"].Value = System.Web.HttpUtility.UrlEncode(staff.userName);
                            Response.Cookies["userName"].Expires = DateTime.Now.AddHours(12);

                            return Redirect("/Home/Index");
                        }
                        else
                        {
                            ViewData["Tip"] = "密码错误！";
                            return View();
                        }
                    }

                    else
                    {
                        ViewData["Tip"] = "用户不存在或者已被冻结！";
                        return View();
                    }

                }
                else
                {
                    return Redirect("/Home/Index");
                }
            }
            else
            {
                ViewData["Tip"] = "用户名密码未填完整！";
                return View();
            }
        }
        //退出登录
        public ActionResult LoginOut()
        {
            Session.Clear();
            //取消Session会话
            Session.Abandon();
            //删除Forms验证票证
            FormsAuthentication.SignOut();
            Response.Cookies["staffID"].Expires = DateTime.Now.AddHours(-12);
            Response.Cookies["staffName"].Expires = DateTime.Now.AddHours(-12);
            Response.Cookies["userName"].Expires = DateTime.Now.AddHours(-12);

            return RedirectToRoute(new { controller = "User", action = "Login" });//    
        }
    }
   
    
}
