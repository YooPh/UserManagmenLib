using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserManagmenLib
{
    /// <summary>
    /// 用户信息实体类
    /// </summary>
    public class User
    {
        /// <summary>
        /// 账号名称
        /// </summary>
        public string UserId { get; set; } = " ";
        /// <summary>
        /// 用户姓名
        /// </summary>
        public string UserName { get; set; } = " ";
        /// <summary>
        /// 账号身份
        /// </summary>
        public int UserPermission { get; set; } = (int)UserPermissionType.操作员;
        /// <summary>
        /// 帐号密码
        /// </summary>
        public string UserPassword { get; set; }
        /// <summary>
        /// 联系号码
        /// </summary>
        public string PhoneNum { get; set; }
        /// <summary>
        /// 账号状态 1可用  0冻结
        /// </summary>
        public int UserState { get; set; } = 0;
        /// <summary>
        /// 账号创建时间
        /// </summary>
        public string CreateDate { get; set; }
        /// <summary>
        /// 权限管理值
        /// </summary>
        public int AuthorityValue { get; set; } = 0;
        /// <summary>
        /// 用户权限等级枚举
        /// </summary>
        public enum UserPermissionType
        {
            操作员 = 0,
            工程师 = 1,
            管理员 = 2,
            超级管理员 = 3
        }
    }
}
