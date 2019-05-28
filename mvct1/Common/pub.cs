using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

using System.Text;
using System.Security;
using System.Security.Cryptography;

namespace MVCtest.Common
{
    public class pub
    {
        public static string Md5Encrypt(string str)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] palindata = Encoding.Default.GetBytes(str);//将要加密的字符串转换为字节数组
            byte[] encryptData = md5.ComputeHash(palindata);//将字符串加密后也转换为字符数组
            string returnData = Convert.ToBase64String(encryptData);//将加密后的字节数组转换为加密字符串
            return returnData;
        }
    }
}