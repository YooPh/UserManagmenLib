using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace UserManagmenLib
{
    /// <summary>
    /// 用户权限管理 超级管理员账号"msw" 密码"msw6256530"
    /// </summary>
    public class UserManagmen
    {
        #region 字段属性

        /// <summary>
        /// 当前登录用户
        /// </summary>
        public User ActiveUser { get; set; }

        /// <summary>
        /// 创建DAL数据操作层
        /// </summary>
        UserDalBase userDal;

        /// <summary>
        /// 权限分配集合
        /// </summary>
        public List<string> AuthorityNames = new List<string>();

        #endregion

        /// <summary>
        /// 通过字符串查找权限
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public bool GetAuthorityRes(string str)
        {
            int index = AuthorityNames.FindIndex((string s) => s == str);
            if (((ActiveUser.AuthorityValue>>index)&1)==0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        #region 信息存储类型选择枚举
        /// <summary>
        /// 信息存储类型选择
        /// </summary>
        public enum DalType
        {
            SqlServer
        }
        #endregion

        #region 代码枚举
        /// <summary>
        /// 返回代码枚举
        /// </summary>
        public enum CodeNum
        {
            OK = 0,
            权限受限 = 1,
            账号密码错误 = 2,
            账号不存在 = 3,
            存在相同账号 = 4,
            权限小于修改后 = 5,
            无法修改权限 = 6,
            用户数据异常=7,
            未登录账号=8
        }
        #endregion

        #region 用户权限管理构造函数
        /// <summary>
        /// 用户权限管理构造函数
        /// </summary>
        /// <param name="type">信息存储类型选择</param>
        /// <param name="path">数据库文件保存路径例如(软件根目录\\SqlData)</param>
        public UserManagmen(DalType type, string path)
        {
            switch (type)
            {
                case DalType.SqlServer:
                    userDal = new UserDal_SqlServer(path);
                    break;
                default:
                    break;
            }

        }
        #endregion

        #region 账号登录
        /// <summary>
        /// 账号登录操作
        /// </summary>
        /// <param name="userName">登录用户名</param>
        /// <param name="userPwd">登录用户密码</param>
        /// <returns></returns>
        public bool UserLogin(string userName, string userPwd)
        {
            int res = userDal.UserLogin(userName, userPwd, out User user);
            if (res == 0 && user != null)
            {
                ActiveUser = user;
                return true;
            }
            else
            {
                return false;
            }
        }
        #endregion

        #region 退出登录
        /// <summary>
        /// 退出登录
        /// </summary>
        public void UserLogout()
        {
            ActiveUser = null;
        }
        #endregion

        #region 添加用户信息
        /// <summary>
        /// 添加新用户 0:添加用户成功 1:权限不足 4:存在相同的账号 7:用户数据异常
        /// </summary>
        /// <param name="user">添加的用户实体</param>
        /// <returns>0:添加用户成功 1:权限不足 4:存在相同的账号 7:用户数据异常</returns>
        public int AddUser(User user)
        {
            if (ActiveUser==null)
            {
                return (int)CodeNum.未登录账号;
            }
            if (user.UserName.Trim()=="" || user.UserPassword.Trim()=="")
            {
                return (int)CodeNum.用户数据异常;
            }
            //比较权限
            if ((int)ActiveUser.UserPermission > (int)user.UserPermission)
            {
                return userDal.AddUser(user);
            }
            else
            {
                return (int)CodeNum.权限受限;
            }
        }
        #endregion

        #region 删除用户信息
        /// <summary>
        /// 删除用户 0:删除用户成功  1:权限不足 3:账号不存在 7:用户数据异常
        /// </summary>
        /// <param name="user"></param>
        /// <returns>0:删除用户成功  1:权限不足 3:账号不存在 7:用户数据异常</returns>
        public int DelUser(User user)
        {
            if (ActiveUser == null)
            {
                return (int)CodeNum.未登录账号;
            }
            if (user.UserName.Trim() == "" || user.UserPassword.Trim() == "")
            {
                return (int)CodeNum.用户数据异常;
            }
            User tempUser = FindUserByUserName(user.UserId);
            if ((int)ActiveUser.UserPermission > (int)tempUser.UserPermission)
            {
                return userDal.DelUser(user);
            }
            else
            {
                return (int)CodeNum.权限受限;
            }
        }

        /// <summary>
        /// 删除用户 0:删除用户成功 1:权限不足 3:账号不存在 7:用户数据异常
        /// </summary>
        /// <param name="userName"></param>
        /// <returns>0：删除用户成功 1:权限不足 3:账号不存在 7:用户数据异常</returns>
        public int DelUser(string userName)
        {
            if (ActiveUser == null)
            {
                return (int)CodeNum.未登录账号;
            }
            if (userName.Trim()=="")
            {
                return (int)CodeNum.用户数据异常;
            }
            int res = userDal.FindUserByUsername(userName, out User user);
            if (res == 0)
            {
                if ((int)ActiveUser.UserPermission > (int)user.UserPermission)
                {
                    return userDal.DelUser(user);
                }
                else
                {
                    return (int)CodeNum.权限受限;
                }
            }
            else
            {
                return res;
            }
        }
        #endregion

        #region 修改用户信息
        /// <summary>
        /// 修改用户 0:修改用户信息完成 1:权限不足 3:修改前的账号信息不存在 4:修改后存在相同账号信息 7:用户数据异常
        /// </summary>
        /// <param name="oldUser">旧的用户实体</param>
        /// <param name="newUser">修改后的用户实体</param>
        /// <returns>0:修改用户信息完成 1:权限不足 3:修改前的账号信息不存在 4:修改后存在相同账号信息 7:用户数据异常</returns>
        public int AltUser(User oldUser, User newUser)
        {
            if (ActiveUser == null)
            {
                return (int)CodeNum.未登录账号;
            }
            if (oldUser.UserName.Trim() == "" || oldUser.UserPassword.Trim() == "" || newUser.UserName.Trim() == "" || newUser.UserPassword.Trim() == "")
            {
                return (int)CodeNum.用户数据异常;
            }
            if ((int)ActiveUser.UserPermission > (int)oldUser.UserPermission)  //当前登录权限大于旧账号
            {
                if ((int)ActiveUser.UserPermission > (int)newUser.UserPermission)  //当前登录权限大于修改后的账号
                {
                    return userDal.AltUser(oldUser, newUser);
                }
                else
                {
                    return (int)CodeNum.权限小于修改后;
                }
            }
            else if ((int)ActiveUser.UserPermission == (int)oldUser.UserPermission && ActiveUser.UserName == oldUser.UserName)  //当前登录权限及用户名都相同
            {
                if ((int)ActiveUser.UserPermission >= (int)newUser.UserPermission)  //当前登录权限大于等于修改后的权限
                {
                    return userDal.AltUser(oldUser, newUser);
                }
                else
                {
                    return (int)CodeNum.无法修改权限;
                }
            }
            else
            {
                return (int)CodeNum.权限受限;
            }
        }

        /// <summary>
        /// 修改用户 0:修改用户信息完成 1:权限不足 3:修改前的账号信息不存在 4:修改后存在相同账号信息 7:用户数据异常
        /// </summary>
        /// <param name="userName">旧的用户名</param>
        /// <param name="newUser">修改后的用户实体</param>
        /// <returns>0:修改用户信息完成 1:权限不足 3:修改前的账号信息不存在 4:修改后存在相同账号信息 7:用户数据异常</returns>
        public int AltUser(string userName, User newUser)
        {
            if (ActiveUser == null)
            {
                return (int)CodeNum.未登录账号;
            }

            if (userName.Trim() == "" || newUser.UserName.Trim() == "" || newUser.UserPassword.Trim() == "")
            {
                return (int)CodeNum.用户数据异常;
            }

            int res = userDal.FindUserByUsername(userName, out User oldUser);
            if (res == 0)
            {
                if ((int)ActiveUser.UserPermission > (int)oldUser.UserPermission)  //当前登录权限大于旧账号
                {
                    if ((int)ActiveUser.UserPermission > (int)newUser.UserPermission)  //当前登录权限大于修改后的账号
                    {
                        return userDal.AltUser(oldUser, newUser);
                    }
                    else
                    {
                        return (int)CodeNum.权限小于修改后;
                    }
                }
                else if ((int)ActiveUser.UserPermission == (int)oldUser.UserPermission && ActiveUser.UserName == oldUser.UserName)  //当前登录权限及用户名都相同
                {
                    if ((int)ActiveUser.UserPermission == (int)newUser.UserPermission)  //当前登录权限等于修改后的权限
                    {
                        return userDal.AltUser(oldUser, newUser);
                    }
                    else
                    {
                        return (int)CodeNum.无法修改权限;
                    }
                }
                else
                {
                    return (int)CodeNum.权限受限;
                }
            }
            else
            {
                return res;
            }
        }
        #endregion

        #region 查找用户信息
        /// <summary>
        /// 获取所有用户信息
        /// </summary>
        /// <returns></returns>
        public DataTable GetAllUserInfo()
        {
            return userDal.GetAllUserInfo();
        }

        /// <summary>
        /// 通过账号名查找
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public User FindUserByUserName(string name)
        {
            if(userDal.FindUserByUsername(name, out User user)==(int)CodeNum.OK)
            {
                return user;
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="permission"></param>
        /// <returns></returns>
        public DataTable FindUserByPermission(int permission)
        {
            if(userDal.FindUserByUserpermission(permission,out DataTable dt)==(int)CodeNum.OK)
            {
                return dt;
            }
            else
            {
                return new DataTable();
            }
        }
        #endregion

        #region SqlServer操作用户数据类
        /// <summary>
        /// 通过数据库操作
        /// </summary>
        class UserDal_SqlServer : UserDalBase
        {
            /// <summary>
            /// 创建数据库时使用
            /// </summary>
            private readonly string connStr1 = "Data Source=localhost;User ID=sa;Password=XMMSW20150625";
            /// <summary>
            /// 连接数据库时使用
            /// </summary>
            private readonly string connStr2 = "Data Source=localhost;Initial Catalog=UserInfoDatabase;User ID=sa;Password=XMMSW20150625";

            public UserDal_SqlServer(string path)
            {
                #region 创建数据库存储文件夹
                if (!Directory.Exists(path))
                {
                    Directory.CreateDirectory(path);
                }
                #endregion

                #region 判断数据库是否存在，不存在则创建 UserInfoDatabase
                string sql = $@"if not exists(select * from master.sys.databases t where t.name='UserInfoDatabase')
                                begin
	                                create database UserInfoDatabase on primary (name = N'UserInfoDatabase',filename=N'{path}\UserInfoDatabase.mdf',size = 5120KB, filegrowth = 1024Kb)
		                            log on (name = N'UserInfoDatabase_log',filename = N'{path}\UserInfoDatabase_log.ldf',size = 1024KB,filegrowth = 10%)
                                end";

                SQLHelper.Update(sql, connStr1);
                #endregion

                #region 判断数据表是否存在，不存在则创建UserInfoTable
                sql = @"if OBJECT_ID('UserInfoTable') is null 
                        create table  UserInfoTable
                        (
                            UserId varchar(max),
                            UserPassword varchar(max),
                            UserPermission int,
                            UserName varchar(max) ,
                            PhoneNum varchar(max),
                            UserState bit,
                            AuthorityValue int,
                            CreateDate varchar(max)
                        )";

                SQLHelper.Update(sql, connStr2);
                #endregion

                #region 判断超级账号是否存在
                sql = "select * from UserInfoTable where UserName ='msw'";
                DataTable dt = SQLHelper.GetDataTable(sql, connStr2);
                if (dt.Rows.Count <= 0)
                {
                    sql = $"insert into UserInfoTable (UserId,UserPassword,UserPermission,UserName,PhoneNum,UserState,AuthorityValue,CreateDate) values ('msw','msw6256530',3,'msw','6256530',1,0,'{DateTime.Now.ToLongDateString()}')";
                    SQLHelper.Update(sql, connStr2);
                }
                #endregion
            }

            #region 查找用户信息
            /// <summary>
            /// 查找用户
            /// </summary>
            /// <param name="userName"></param>
            /// <param name="userPwd"></param>
            /// <returns>代码0:查找完成 2:账号密码错误</returns>
            public override int UserLogin(string userName, string userPwd, out User user)
            {
                string sql = $"select * from UserInfoTable where UserId ='{userName}' and UserPassword = '{userPwd}'";
                DataTable dt = SQLHelper.GetDataTable(sql, connStr2);
                user = new User();
                if (dt.Rows.Count > 0)
                {
                    user.UserId = dt.Rows[0]["UserId"].ToString();
                    user.UserPassword = dt.Rows[0]["UserPassword"].ToString();
                    user.UserPermission = Convert.ToInt32(dt.Rows[0]["UserPermission"]);
                    user.UserName = dt.Rows[0]["UserName"].ToString();
                    user.PhoneNum = dt.Rows[0]["PhoneNum"].ToString();
                    user.UserState = Convert.ToInt32(dt.Rows[0]["UserState"]);
                    user.AuthorityValue = Convert.ToInt32(dt.Rows[0]["AuthorityValue"]);
                    user.CreateDate = dt.Rows[0]["CreateDate"].ToString();
                    return (int)CodeNum.OK;
                }
                else
                {
                    return (int)CodeNum.账号密码错误;
                }
            }
            
            /// <summary>
            /// 查找用户
            /// </summary>
            /// <param name="userName"></param>
            /// <returns>代码0:查找完成 3:查找的信息不存在</returns>
            public override int FindUserByUsername(string userName, out User user)
            {
                string sql = $"select * from UserInfoTable where UserId ='{userName}'";
                DataTable dt = SQLHelper.GetDataTable(sql, connStr2);
                user = new User();
                if (dt.Rows.Count > 0)
                {
                    user.UserId = dt.Rows[0]["UserId"].ToString();
                    user.UserPassword = dt.Rows[0]["UserPassword"].ToString();
                    user.UserPermission = Convert.ToInt32(dt.Rows[0]["UserPermission"]);
                    user.UserName = dt.Rows[0]["UserName"].ToString();
                    user.PhoneNum = dt.Rows[0]["PhoneNum"].ToString();
                    user.UserState = Convert.ToInt32(dt.Rows[0]["UserState"]);
                    user.AuthorityValue = Convert.ToInt32(dt.Rows[0]["AuthorityValue"]);
                    user.CreateDate = dt.Rows[0]["CreateDate"].ToString();
                    return (int)CodeNum.OK;
                }
                else
                {
                    return (int)CodeNum.账号不存在;
                }
            }

            /// <summary>
            /// 查找用户 
            /// </summary>
            /// <param name="userPermission"></param>
            /// <param name="user"></param>
            /// <returns>代码0:查找完成 3:查找的信息不存在</returns>
            public override int FindUserByUserpermission(int userPermission, out DataTable userTable)
            {
                string sql = $"select * from UserInfoTable where UserPermission = {userPermission}";
                DataTable dt = SQLHelper.GetDataTable(sql, connStr2);
                userTable = new DataTable();
                if (dt.Rows.Count > 0)
                {
                    userTable = dt.Copy();
                    return (int)CodeNum.OK;
                }
                else
                {
                    return (int)CodeNum.账号不存在;
                }
            }

            /// <summary>
            /// 获取所有用户信息
            /// </summary>
            /// <returns></returns>
            public override DataTable GetAllUserInfo()
            {
                string sql = "select * from UserInfoTable";
                return SQLHelper.GetDataTable(sql, connStr2);
            }
            #endregion

            #region 添加用户信息
            /// <summary>
            /// 添加用户
            /// </summary>
            /// <param name="user"></param>
            /// <returns>代码0:添加用户完成 4:存在相同的账号</returns>
            public override int AddUser(User user)
            {
                string sql = $"select * from UserInfoTable where UserId ='{user.UserId}'";
                DataTable dt = SQLHelper.GetDataTable(sql, connStr2);
                if (dt.Rows.Count <= 0)
                {
                    sql = $"insert into UserInfoTable (UserId,UserPassword,UserPermission,UserName,PhoneNum,UserState,AuthorityValue,CreateDate) values ('{user.UserId}','{user.UserPassword}','{user.UserPermission}','{user.UserName}','{user.PhoneNum}',{user.UserState},{user.AuthorityValue},'{DateTime.Now.ToLongDateString()}')";
                    SQLHelper.Update(sql, connStr2);
                    return (int)CodeNum.OK;
                }
                else
                {
                    return (int)CodeNum.存在相同账号;
                }
            }
            #endregion

            #region 删除用户信息
            /// <summary>
            /// 删除用户
            /// </summary>
            /// <param name="user"></param>
            /// <returns>代码0:删除用户完成 3:账号不存在</returns>
            public override int DelUser(User user)
            {
                string sql = $"select * from UserInfoTable where UserId ='{user.UserId}'";
                DataTable dt = SQLHelper.GetDataTable(sql, connStr2);
                
                if (dt.Rows.Count > 0)
                {
                    sql = $"delete from UserInfoTable where UserId = '{user.UserId}'";
                    SQLHelper.Update(sql, connStr2);
                    return (int)CodeNum.OK;
                }
                else
                {
                    return (int)CodeNum.账号不存在;
                }
            }
            #endregion

            #region 修改用户信息
            /// <summary>
            /// 修改用户
            /// </summary>
            /// <param name="oldUser"></param>
            /// <param name="newUser"></param>
            /// <returns>代码0:修改用户信息完成 3:修改前的账号信息不存在 4:修改后存在相同账号信息</returns>
            public override int AltUser(User oldUser, User newUser)
            {
                string sql = $"select * from UserInfoTable where UserId ='{oldUser.UserId}'";
                DataTable dt = SQLHelper.GetDataTable(sql, connStr2);
                if (dt.Rows.Count > 0)
                {
                    sql = $"select * from UserInfoTable where UserId ='{newUser.UserId}'";
                    dt = SQLHelper.GetDataTable(sql, connStr2);
                    if (dt.Rows.Count <= 0 || dt.Rows[0]["UserId"].ToString()==oldUser.UserId)
                    {
                        sql = $"update UserInfoTable set UserId = '{newUser.UserId}', UserPassword = '{newUser.UserPassword}' , UserPermission = '{newUser.UserPermission}', UserName = '{newUser.UserName}', PhoneNum = '{newUser.PhoneNum}' , UserState = {newUser.UserState},AuthorityValue = {newUser.AuthorityValue} where UserId ='{oldUser.UserId}'";
                        SQLHelper.Update(sql, connStr2);
                        return (int)CodeNum.OK;
                    }
                    else
                    {
                        return (int)CodeNum.存在相同账号;
                    }
                }
                else
                {
                    return (int)CodeNum.账号不存在;
                }
            }
            #endregion

            
        }
        #endregion

        #region 用户数据操作基类
        /// <summary>
        /// 用户管理数据操作层基类
        /// </summary>
        public abstract class UserDalBase
        {
            /// <summary>
            /// 查找用户
            /// </summary>
            /// <param name="userName"></param>
            /// <param name="userPwd"></param>
            /// <returns></returns>
            public abstract int UserLogin(string userName, string userPwd, out User user);

            /// <summary>
            /// 查找用户
            /// </summary>
            /// <param name="userName"></param>
            /// <returns></returns>
            public abstract int FindUserByUsername(string userName, out User user);

            /// <summary>
            /// 查找用户
            /// </summary>
            /// <param name="userPermission"></param>
            /// <returns></returns>
            public abstract int FindUserByUserpermission(int userPermission, out DataTable userTable);

            /// <summary>
            /// 添加用户
            /// </summary>
            /// <param name="user"></param>
            /// <returns></returns>
            public abstract int AddUser(User user);

            /// <summary>
            /// 删除用户
            /// </summary>
            /// <param name="user"></param>
            /// <returns></returns>
            public abstract int DelUser(User user);

            /// <summary>
            /// 修改用户
            /// </summary>
            /// <param name="oldUser"></param>
            /// <param name="newUser"></param>
            /// <returns></returns>
            public abstract int AltUser(User oldUser, User newUser);

            /// <summary>
            /// 获取所有用户信息
            /// </summary>
            /// <returns></returns>
            public abstract DataTable GetAllUserInfo();

        }
        #endregion

        #region SqlHelper类
        /// <summary>
        /// 访问 SQL Server 数据通用类
        /// </summary>
        public class SQLHelper
        {
            //定义连接字符串(在App.config配置文件中)
            public static readonly string connString = "Data Source=localhost;User ID=sa;Password=XMMSW20150625";

            #region 格式化 SQL 语句执行方法
            /// <summary>
            /// 执行增删改操作(insert/update/delect)。返回受影响行数
            /// </summary>
            /// <param name="sql">sql语句</param>
            /// <returns>返回受影响行数</returns>
            public static int Update(string sql, string connStr)
            {
                SqlConnection conn = new SqlConnection(connStr);
                SqlCommand cmd = new SqlCommand(sql, conn);
                try
                {
                    conn.Open();
                    return cmd.ExecuteNonQuery();
                }
                catch (Exception ex)
                {
                    string error = "调用 public static int Update(string sql) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
                finally
                {
                    if (conn.State == ConnectionState.Open)
                    {
                        conn.Close();
                    }
                }
            }

            /// <summary>
            /// 执行单一结果查询。返回一个 object 对象
            /// </summary>
            /// <param name="sql">sql语句</param>
            /// <returns>返回一个 object 对象</returns>
            public static object GetSingleResult(string sql)
            {
                SqlConnection conn = new SqlConnection(connString);
                SqlCommand cmd = new SqlCommand(sql, conn);
                try
                {
                    conn.Open();
                    return cmd.ExecuteScalar();
                }
                catch (Exception ex)
                {
                    string error = "调用 public static object GetSingleResult(string sql) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
                finally
                {
                    if (conn.State == ConnectionState.Open)
                    {
                        conn.Close();
                    }
                }
            }

            /// <summary>
            /// 执行结果集查询。返回一个 SqlDataReader 对象
            /// </summary>
            /// <param name="sql">sql语句</param>
            /// <returns>返回一个 SqlDataReader 对象</returns>
            public static SqlDataReader GetReader(string sql)
            {
                SqlConnection conn = new SqlConnection(connString);
                SqlCommand cmd = new SqlCommand(sql, conn);
                try
                {
                    conn.Open();
                    //conn.Close();//在获取结果前不能释放
                    //传入"CommandBehavior.CloseConnection"，参数能够保证从外部关闭 DataReader 时，与之关联的 Connection 对象随之关闭
                    return cmd.ExecuteReader(CommandBehavior.CloseConnection);
                }
                catch (Exception ex)
                {
                    if (conn.State == ConnectionState.Open)//异常时才关闭
                    {
                        conn.Close();
                    }

                    string error = "调用 public static SqlDataReader GetReader(string sql) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
            }

            /// <summary>
            /// 执行返回数据集的查询。返回一个 DataSet 对象
            /// </summary>
            /// <param name="sql">sql语句</param>
            /// <returns>返回一个 DataSet 对象</returns>
            public static DataSet GetDataSet(string sql)
            {
                SqlConnection conn = new SqlConnection(connString);
                SqlCommand cmd = new SqlCommand(sql, conn);
                SqlDataAdapter da = new SqlDataAdapter(cmd);//创建数据数据器对象
                DataSet ds = new DataSet();//创建一个内存数据集

                try
                {
                    conn.Open();
                    da.Fill(ds);//使用数据适配器填充数据集
                    return ds;
                }
                catch (Exception ex)
                {
                    string error = "调用 public static DataSet GetDataSet(string sql) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
                finally
                {
                    if (conn.State == ConnectionState.Open)
                    {
                        conn.Close();
                    }
                }
            }

            /// <summary>
            /// 执行返回数据集的查询。返回一个 DataSet 对象
            /// </summary>
            /// <param name="sql">sql语句</param>
            /// <returns>返回一个 DataSet 对象</returns>
            public static DataTable GetDataTable(string sql, string connStr)
            {
                SqlConnection conn = new SqlConnection(connStr);
                SqlCommand cmd = new SqlCommand(sql, conn);
                SqlDataAdapter da = new SqlDataAdapter(cmd);//创建数据数据器对象
                DataTable dt = new DataTable();//创建一个内存数据表

                try
                {
                    conn.Open();
                    da.Fill(dt);//使用数据适配器填充数据集
                    return dt;
                }
                catch (Exception ex)
                {
                    string error = "调用 public static DataTable GetDataTable(string sql) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
                finally
                {
                    if (conn.State == ConnectionState.Open)
                    {
                        conn.Close();
                    }
                }
            }

            /// <summary>
            /// 获取数据库服务的时间。返回 DateTime 对象
            /// </summary>
            /// <returns>返回 DateTime 对象</returns>
            public static DateTime GetServerTime()
            {
                return Convert.ToDateTime(GetSingleResult("select getdate()"));
            }
            #endregion

            #region 带参数 SQL 语句执行方法
            /// <summary>
            /// 执行增删改操作(insert/update/delect)。返回受影响行数
            /// </summary>
            /// <param name="sql">sql语句</param>
            /// <param name="param">参数数组</param>
            /// <returns>返回受影响行数</returns>
            public static int Update(string sql, SqlParameter[] param)
            {
                SqlConnection conn = new SqlConnection(connString);
                SqlCommand cmd = new SqlCommand(sql, conn);

                try
                {
                    conn.Open();
                    cmd.Parameters.AddRange(param);//添加参数数组
                    int result = cmd.ExecuteNonQuery();
                    return result;

                }
                catch (SqlException ex)
                {
                    string error = "调用 public static int Update(string sql, SqlParameter[] param) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
                finally
                {
                    if (conn.State == ConnectionState.Open)
                    {
                        conn.Close();
                    }
                }
            }

            /// <summary>
            /// 执行单一结果查询。返回一个 object 对象
            /// </summary>
            /// <param name="sql">sql语句</param>
            /// <param name="param">参数数组</param>
            /// <returns>返回一个 object 对象</returns>
            public static object GetSingleResult(string sql, SqlParameter[] param)
            {
                SqlConnection conn = new SqlConnection(connString);
                SqlCommand cmd = new SqlCommand(sql, conn);
                try
                {
                    conn.Open();
                    cmd.Parameters.AddRange(param);
                    return cmd.ExecuteScalar();
                }
                catch (Exception ex)
                {
                    string error = "调用 public static object GetSingleResult(string sql, SqlParameter[] param) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
                finally
                {
                    if (conn.State == ConnectionState.Open)
                    {
                        conn.Close();
                    }
                }
            }

            /// <summary>
            /// 执行结果集查询。返回一个 SqlDataReader 对象
            /// </summary>
            /// <param name="sql">sql语句</param>
            /// <param name="param">参数数组</param>
            /// <returns>返回一个 SqlDataReader 对象</returns>
            public static SqlDataReader GetReader(string sql, SqlParameter[] param)
            {
                SqlConnection conn = new SqlConnection(connString);
                SqlCommand cmd = new SqlCommand(sql, conn);
                try
                {
                    conn.Open();
                    cmd.Parameters.AddRange(param);
                    //conn.Close();//在获取结果前不能释放
                    //传入"CommandBehavior.CloseConnection"，参数能够保证从外部关闭 DataReader 时，与之关联的 Connection 对象随之关闭
                    return cmd.ExecuteReader(CommandBehavior.CloseConnection);
                }
                catch (Exception ex)
                {
                    if (conn.State == ConnectionState.Open)//异常时才关闭
                    {
                        conn.Close();
                    }

                    string error = "调用 public static SqlDataReader GetReader(string sql, SqlParameter[] param) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
            }

            /// <summary>
            /// 执行返回数据集的查询。返回一个 DataSet 对象
            /// </summary>
            /// <param name="sql">sql语句</param>
            /// <param name="param">参数数组</param>
            /// <returns>返回一个 DataSet 对象</returns>
            public static DataSet GetDataSet(string sql, SqlParameter[] param)
            {
                SqlConnection conn = new SqlConnection(connString);
                SqlCommand cmd = new SqlCommand(sql, conn);
                cmd.Parameters.AddRange(param);
                SqlDataAdapter da = new SqlDataAdapter(cmd);//创建数据数据器对象
                DataSet ds = new DataSet();//创建一个内存数据集

                try
                {
                    conn.Open();
                    da.Fill(ds);//使用数据适配器填充数据集
                    return ds;
                }
                catch (Exception ex)
                {
                    string error = "调用 public static DataSet GetDataSet(string sql, SqlParameter[] param) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
                finally
                {
                    if (conn.State == ConnectionState.Open)
                    {
                        conn.Close();
                    }
                }
            }

            /// <summary>
            /// 执行返回数据集的查询。返回一个 DataSet 对象
            /// </summary>
            /// <param name="sql">sql语句</param>
            /// <param name="param">参数数组</param>
            /// <returns>返回一个 DataSet 对象</returns>
            public static DataTable GetDataTable(string sql, SqlParameter[] param)
            {
                SqlConnection conn = new SqlConnection(connString);
                SqlCommand cmd = new SqlCommand(sql, conn);
                cmd.Parameters.AddRange(param);
                SqlDataAdapter da = new SqlDataAdapter(cmd);//创建数据数据器对象
                DataTable dt = new DataTable();//创建一个内存数据集

                try
                {
                    conn.Open();
                    da.Fill(dt);//使用数据适配器填充数据集
                    return dt;
                }
                catch (Exception ex)
                {
                    string error = "调用 public static DataTable GetDataTable(string sql, SqlParameter[] param) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
                finally
                {
                    if (conn.State == ConnectionState.Open)
                    {
                        conn.Close();
                    }
                }
            }

            /// <summary>
            /// 启用事务提交带多条参数的 SQL 语句
            /// </summary>
            /// <param name="mainSql">主表 SQL 语句</param>
            /// <param name="mainParam">主表 SQL 语句对应的参数</param>
            /// <param name="detailSql">明细表 SQL 语句</param>
            /// <param name="detailParam">明细表 SQL 语句对应的参数数组集合</param>
            /// <returns>返回事务是否执行成功</returns>
            public static bool UpdateByTran(string mainSql, SqlParameter[] mainParam, string detailSql, List<SqlParameter[]> detailParam)
            {
                SqlConnection conn = new SqlConnection();
                SqlCommand cmd = new SqlCommand();
                cmd.Connection = conn;

                try
                {
                    conn.Open();
                    cmd.Transaction = conn.BeginTransaction();//开启事务
                    if (mainParam != null && mainSql.Length != 0)
                    {
                        cmd.CommandText = mainSql;
                        cmd.Parameters.AddRange(mainParam);
                        cmd.ExecuteNonQuery();
                    }
                    foreach (SqlParameter[] param in detailParam)
                    {
                        cmd.CommandText = detailSql;
                        cmd.Parameters.Clear();//必须要清除以前的参数
                        cmd.Parameters.AddRange(param);
                        cmd.ExecuteNonQuery();
                    }
                    cmd.Transaction.Commit();//提交事务
                    return true;
                }
                catch (Exception ex)
                {
                    if (cmd.Transaction != null)
                    {
                        cmd.Transaction.Rollback();//回滚事务
                    }

                    string error = "调用 public static bool UpdateByTran(string mainSql, SqlParameter[] mainParam, string detailSql, List<SqlParameter[]> detailParam) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
                finally
                {
                    if (cmd.Transaction != null)
                    {
                        cmd.Transaction = null;//清空事务
                    }
                    if (conn.State == ConnectionState.Open)//异常时才关闭
                    {
                        conn.Close();
                    }
                }
            }
            #endregion

            #region 存储过程执行方法
            /// <summary>
            /// 执行存储过程增删改操作(insert/update/delect)。返回受影响行数
            /// </summary>
            /// <param name="procedureName">存储过程名称。需要在数据库创建存储过程</param>
            /// <param name="param">参数数组</param>
            /// <returns>返回受影响行数</returns>
            public static int UpdateByProcedure(string procedureName, SqlParameter[] param)
            {
                SqlConnection conn = new SqlConnection(connString);
                SqlCommand cmd = new SqlCommand(procedureName, conn);
                //cmd.Connection = conn;//(改为实例化时传参)
                //cmd.CommandText = procedureName;//设置存储过程参数(改为实例化时传参)

                try
                {
                    conn.Open();
                    cmd.CommandType = CommandType.StoredProcedure;//设置当前的操作是执行存储过程
                    cmd.Parameters.AddRange(param);//添加参数数组
                    int result = cmd.ExecuteNonQuery();
                    return result;
                }
                catch (SqlException ex)
                {
                    string error = "调用 public static int UpdateByProcedure(string procedureName, SqlParameter[] param) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
                finally
                {
                    if (conn.State == ConnectionState.Open)
                    {
                        conn.Close();
                    }
                }
            }

            /// <summary>
            /// 执行存储过程单一结果查询。返回一个 object 对象
            /// </summary>
            /// <param name="procedureName">存储过程名称。需要在数据库创建存储过程</param>
            /// <param name="param">参数数组</param>
            /// <returns>返回一个 object 对象</returns>
            public static object GetSingleResultByProcedure(string procedureName, SqlParameter[] param)
            {
                SqlConnection conn = new SqlConnection(connString);
                SqlCommand cmd = new SqlCommand(procedureName, conn);
                try
                {
                    conn.Open();
                    cmd.CommandType = CommandType.StoredProcedure;//设置当前的操作是执行存储过程
                    cmd.Parameters.AddRange(param);//添加参数数组
                    return cmd.ExecuteScalar();
                }
                catch (Exception ex)
                {
                    string error = "调用 public static object GetSingleResultByProcedure(string procedureName, SqlParameter[] param) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
                finally
                {
                    if (conn.State == ConnectionState.Open)
                    {
                        conn.Close();
                    }
                }
            }

            /// <summary>
            /// 执行存储过程结果集查询。返回一个 SqlDataReader 对象
            /// </summary>
            /// <param name="procedureName">存储过程名称。需要在数据库创建存储过程</param>
            /// <param name="param">参数数组</param>
            /// <returns>返回一个 SqlDataReader 对象</returns>
            public static SqlDataReader GetReaderByProcedure(string procedureName, SqlParameter[] param)
            {
                SqlConnection conn = new SqlConnection(connString);
                SqlCommand cmd = new SqlCommand(procedureName, conn);
                try
                {
                    conn.Open();
                    cmd.CommandType = CommandType.StoredProcedure;//设置当前的操作是执行存储过程
                    cmd.Parameters.AddRange(param);//添加参数数组
                                                   //conn.Close();//在获取结果前不能释放
                                                   //传入"CommandBehavior.CloseConnection"，参数能够保证从外部关闭 DataReader 时，与之关联的 Connection 对象随之关闭
                    return cmd.ExecuteReader(CommandBehavior.CloseConnection);
                }
                catch (Exception ex)
                {
                    if (conn.State == ConnectionState.Open)//异常时才关闭
                    {
                        conn.Close();
                    }

                    string error = "调用 public static SqlDataReader GetReaderByProcedure(string procedureName, SqlParameter[] param) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
            }

            /// <summary>
            /// 启用事务提交带多条参数的存储过程
            /// </summary>
            /// <param name="procedureName">存储过程名称。需要在数据库创建存储过程</param>
            /// <param name="paramArray">存储过程参数数组集合</param>
            /// <returns>返回基于事务的存储过程调用是否成功</returns>
            public static bool UpdateByTranByProcedure(string procedureName, List<SqlParameter[]> paramArray)
            {
                SqlConnection conn = new SqlConnection();
                SqlCommand cmd = new SqlCommand();
                cmd.Connection = conn;

                try
                {
                    conn.Open();
                    cmd.CommandType = CommandType.StoredProcedure;//设置当前的操作是执行存储过程
                    cmd.CommandText = procedureName;
                    cmd.Transaction = conn.BeginTransaction();//开启事务
                    foreach (SqlParameter[] param in paramArray)
                    {
                        cmd.Parameters.Clear();//必须要清除以前的参数
                        cmd.Parameters.AddRange(param);
                        cmd.ExecuteNonQuery();
                    }
                    cmd.Transaction.Commit();//提交事务
                    return true;
                }
                catch (Exception ex)
                {
                    if (cmd.Transaction != null)
                    {
                        cmd.Transaction.Rollback();//回滚事务
                    }

                    string error = "调用 public static bool UpdateByTranByProcedure(string procedureName, List<SqlParameter[]> paramArray) 方法时发生异常：" + ex.Message;
                    WriteLog(error);//将异常信息写入日志...
                    throw new Exception(error);
                }
                finally
                {
                    if (cmd.Transaction != null)
                    {
                        cmd.Transaction = null;//清空事务
                    }
                    if (conn.State == ConnectionState.Open)//异常时才关闭
                    {
                        conn.Close();
                    }
                }
            }
            #endregion

            #region 其他
            /// <summary>
            /// 异常信息日志
            /// </summary>
            /// <param name="log"></param>
            private static void WriteLog(string log)
            {
                try
                {
                    string path = Directory.GetCurrentDirectory() + "\\SqlHelper.log";
                    if (Directory.Exists(Path.GetDirectoryName(path)))
                    {
                        Directory.CreateDirectory(Path.GetDirectoryName(path));
                    }
                    FileStream fs = new FileStream(path, FileMode.Append);
                    StreamWriter sw = new StreamWriter(fs);
                    sw.WriteLine(DateTime.Now.ToString() + "    " + log);
                    sw.Close();
                    fs.Close();
                }
                catch (Exception ex)
                {
                    string error = "调用 private static void WriteLog(string log) 方法时发生异常：" + ex.Message;
                    throw new Exception(error);
                }
            }
            #endregion
        }
        #endregion
    }
}
