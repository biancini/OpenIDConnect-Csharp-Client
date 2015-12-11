using System.IdentityModel.Services;
using System.Web.Mvc;

namespace SampleApplication.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult SignOut()
        {
            FederatedAuthentication.SessionAuthenticationModule.SignOut();
            return RedirectToAction("Index");
        }
    }
}
