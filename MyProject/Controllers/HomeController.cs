using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using PagedList;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Threading;

namespace MyProject.Controllers
{

    public class HomeController : Controller
    {

        public ActionResult Index()
        {
            return View();
        }

        // GET: /Home/Info/
        [Authorize]
        public ActionResult Info(int? page)
        {

#if DEBUG
            var model = new List<UserInfo>
            {
                new UserInfo { Name = "Name1", Info = "Info1" , Status = false},
                new UserInfo { Name = "Name2", Info = "Info2" , Status = true},
                new UserInfo { Name = "Name3", Info = "Info3" , Status = true },
                new UserInfo { Name = "Name4", Info = "Info4" , Status = false },
                new UserInfo { Name = "Name5", Info = "Info5" , Status = true },
                new UserInfo { Name = "Name6", Info = "Info6" , Status = true }
            };
#else
            ADInfo adinfo = new ADInfo();

            List<UserPrincipal> adlist = adinfo.GetGroup();
            var model = new List<UserInfo>();

            foreach (var item in adlist)
            {
                var status = item.Enabled ?? false;
                model.Add( new UserInfo { Name = item.SamAccountName, Info = item.DistinguishedName, Status = status });
            }

            model.RemoveAll( item => item.Name == "krbtgt" || item.Name == "Administrator" || item.Name == "DefaultAccount" || item.Name == "Guest");
            model.Sort((x, y) => string.Compare(x.Name, y.Name));
#endif
            int pageSize = 10;
            int pageNumber = (page ?? 1);

            return View(model.ToPagedList(pageNumber, pageSize));
        }

        // GET: /Home/Details/
        public ActionResult GetDetails(string name)
        {

#if DEBUG
            UserInfo userInfo = new UserInfo
            {
                Name = name,
                Info = "info",
                Status = true
            };
#else
            ADInfo adinfo = new ADInfo();
            UserPrincipal uP = adinfo.GetUser(name, false);
            var status = uP.Enabled ?? false;
            UserInfo userInfo = new UserInfo
            {
                Name = uP.SamAccountName,
                Info = adinfo.GetOUForUser(name),
                Status = status
            };


#endif
            return PartialView("Details", userInfo);
        }

        // GET: /Home/GetResetPass/
        public ActionResult GetResetPass(string name)
        {
            ModelState.Clear();

            ResetModel rModel = new ResetModel()
            {
                SamAccountName = name
            };

            return PartialView("ResetPassword", rModel);
        }

        // GET: /Home/GetCreateUser
        public ActionResult CreateUser()
        {
            ModelState.Clear();
            ADInfo adinfo = new ADInfo();
            var OUgroup = adinfo.GetOU();

            CreateModel cModel = new CreateModel
            {
                OrgUnit = adinfo.GetSelectListItems(OUgroup)
            };
            return View("CreateUser", cModel) ;
        }





        // POST: /Home/ResetPass
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public ActionResult ResetPass(ResetModel rModel)
        {
            if (ModelState.IsValid)
            {
#if DEBUG
                Debug.WriteLine("Thread sleep now");
                Thread.Sleep(2000);
                Debug.WriteLine("Thread after");
#else
                try
                {
                    ADInfo adinfo = new ADInfo();
                    using (UserPrincipal uP = adinfo.GetUser(rModel.SamAccountName, true))
                    {
                        if (uP != null)
                        {
                            uP.SetPassword(rModel.Password);
                            uP.Save();
                            ViewBag.Message = "Success";
                            ModelState.Clear();
                            return PartialView("_ResetPassword");
                        }
                        ViewBag.Message = "User Not Found";
                        ModelState.Clear();
                        return PartialView("_ResetPassword", rModel);
                    }
                }
                catch (Exception e)
                {
                    ViewBag.Message = e.Message + e.StackTrace + e.InnerException;
                    ModelState.Clear();
                    return PartialView("_ResetPassword", rModel);
                }
#endif

            }
            return PartialView("_ResetPassword", rModel);
        }

        // POST: /Home/CreateUser
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public ActionResult PCreateUser(CreateModel cModel)
        {
            ADInfo adinfo = new ADInfo();
            var OUgroup = adinfo.GetOU();
            cModel.OrgUnit = adinfo.GetSelectListItems(OUgroup);
            string test = cModel.SelectedOU;
            if (ModelState.IsValid)
            {
                try
                {
                    using (UserPrincipal uP = adinfo.GetUser(cModel.SamAccountName, false))
                    {
                        if (uP == null)
                        {
                            PrincipalContext ctx = new PrincipalContext(ContextType.Domain, 
                                "newgate-software.local", 
                                "ou=" + cModel.SelectedOU + ",dc=newgate-software,dc=local", 
                                "NEWGATE-SOFTWAR\\Administrator", 
                                "P@ssw0rd123");
                            UserPrincipal newUser = new UserPrincipal(ctx, cModel.SamAccountName, cModel.Password, true)
                            {
                                GivenName = cModel.DisplayName,
                                PasswordNeverExpires = true,
                                Enabled = true
                            };
                            newUser.Save();

                            ViewBag.Message = "Success";
                            ModelState.Clear();
                            return PartialView("_CreateUser", cModel);
                        }
                        else
                        {
                            ViewBag.Message = "Username existed";
                            ModelState.Clear();
                            return PartialView("_CreateUser", cModel);
                        }
                    }
                }
                catch (Exception e)
                {
                    ViewBag.Message = e.Message + e.StackTrace + e.InnerException;
                    ModelState.Clear();
                    return PartialView("_CreateUser", cModel);
                }
            }
            return PartialView("_CreateUser", cModel);
        }

    }

    internal class ADInfo
    {
        public List<UserPrincipal> GetGroup()
        {
            PrincipalContext oPrincipalContext = GetPrincipalContext();
            List<UserPrincipal> uPrincipals = new List<UserPrincipal>();

#if DEBUG
            PrincipalContext ctx = new PrincipalContext(ContextType.Machine);
#else
            PrincipalContext ctx = new PrincipalContext(ContextType.Domain, "NEWGATE-SOFTWAR", "dc=newgate-software,dc=local");
#endif
            UserPrincipal qbeUser = new UserPrincipal(ctx);
            PrincipalSearcher srch = new PrincipalSearcher(qbeUser);

            foreach (UserPrincipal p in srch.FindAll())
            {
                uPrincipals.Add(p);
            }
            return uPrincipals;
        }

        public UserPrincipal GetUser(string name, bool? adminPriv)
        {

#if DEBUG
            PrincipalContext ctx = new PrincipalContext(ContextType.Machine);
#else
            PrincipalContext ctx = null;
            if (adminPriv == true)
            {
                ctx = new PrincipalContext(ContextType.Domain, "newgate-software.local", "NEWGATE-SOFTWAR\\Administrator", "P@ssw0rd123");
            }
            else
            {
                ctx = new PrincipalContext(ContextType.Domain);
            }
#endif
            UserPrincipal uP = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, name);
            return uP;
        }
        
        public string GetOUForUser(string name)
        {
            PrincipalContext oPrincipalContext = GetPrincipalContext();

#if DEBUG
            PrincipalContext ctx = new PrincipalContext(ContextType.Machine);
#else
            PrincipalContext ctx = new PrincipalContext(ContextType.Domain, "NEWGATE-SOFTWAR", "dc=newgate-software,dc=local");
#endif
            Principal user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, name);

            int startIndex = user.DistinguishedName.IndexOf("OU=", 1) + 3; //+3 for  length of "OU="
            int endIndex = user.DistinguishedName.IndexOf(",", startIndex);
            var group = user.DistinguishedName.Substring((startIndex), (endIndex - startIndex));
            return group;
        }

        public static PrincipalContext GetPrincipalContext()
        {
#if DEBUG
            PrincipalContext oPrincipalContext = new PrincipalContext(ContextType.Machine);
#else
            PrincipalContext oPrincipalContext = new PrincipalContext(ContextType.Domain);
#endif
            return oPrincipalContext;
        }
        
        public IEnumerable<string> GetOU()
        {
#if DEBUG
            List<string> orgUnits = new List<string>();
            List<string> result = new List<string>
            {
                "LDAP://OU=Domain Controllers,DC=123",
                "LDAP://OU=Marke ting,DC=123",
                "LDAP://OU=GG,DC=123",
                "LDAP://OU=Test,DC=123",
                "LDAP://OU=LOL,DC=123",
                "LDAP://OU= ,DC=123"
            };

            foreach (String s in result)
            {
                Regex regex = new Regex(@"(?<=OU=)(.[\w ]+)(?=,)");
                Match match = regex.Match(s);
                if (match.Value.Length != 0 && !String.Equals(match.Value, "Domain Controllers"))
                {
                    Debug.WriteLine(match.Value);
                    orgUnits.Add(match.Value);
                }
            }
            return orgUnits;
#else
            List<string> orgUnits = new List<string>();

            DirectoryEntry startingPoint = new DirectoryEntry("LDAP://DC=newgate-software,DC=local");

            DirectorySearcher searcher = new DirectorySearcher(startingPoint)
            {
                Filter = "(objectCategory=organizationalUnit)"
            };

            foreach (SearchResult res in searcher.FindAll())
            {
                Regex regex = new Regex(@"(?<=OU=)(.[\w ]+)(?=,)");
                Match match = regex.Match(res.Path);
                if (match.Value.Length != 0 && !String.Equals(match.Value, "Domain Controllers"))
                {
                    orgUnits.Add(match.Value);
                }
            }
            return orgUnits;
#endif
        }

        public IEnumerable<SelectListItem> GetSelectListItems(IEnumerable<string> elements)
        {
            var selectList = new List<SelectListItem>();
            foreach (var element in elements)
            {
                selectList.Add(new SelectListItem
                {
                    Value = element,
                    Text = element
                });
            }
            return selectList;
        }
    }

    public class UserInfo
    {
        public string Name { get; set; }
        public string Info { get; set; }
        public Boolean Status { get; set; }
    }

    public class ResetModel
    {
        public string SamAccountName { get; set; }
        [Required(ErrorMessage = "Please Enter New Password")]
        [StringLength(20, ErrorMessage = "Password must be between 8 and 20 characters", MinimumLength = 8)]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [Required(ErrorMessage = "Please Enter Confirmation Password")]
        [StringLength(20, ErrorMessage = "Confirmation Password must be between 8 and 20 characters", MinimumLength = 8)]
        [DataType(DataType.Password)]
        [System.ComponentModel.DataAnnotations.Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string SecPass { get; set; }
    }

    public class CreateModel
    {
        [Required(ErrorMessage = "Please Enter Username")]
        public string SamAccountName { get; set; }
        [Required(ErrorMessage = "Please Enter New Password")]
        [StringLength(20, ErrorMessage = "Password must be between 8 and 20 characters", MinimumLength = 8)]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [Required(ErrorMessage = "Please Enter Confirmation Password")]
        [StringLength(20, ErrorMessage = "Confirmation Password must be between 8 and 20 characters", MinimumLength = 8)]
        [DataType(DataType.Password)]
        [System.ComponentModel.DataAnnotations.Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string SecPass { get; set; }
        [Required(ErrorMessage = "Please Enter Display Name")]
        public string DisplayName { get; set; }
        public IEnumerable<SelectListItem> OrgUnit { get; set; }
        [Required]
        public string SelectedOU { get; set; }
    }
}