# from django.shortcuts import render, HttpResponse
# from .models import TodoItem

# # Create your views here.
# def home(request):
#     return render(request, "home.html")

# def todos(request):
#     items = TodoItem.objects.all()
#     return render(request, "todos.html", {"todos": items})


# views.py
from django.shortcuts import render
from .security_checker import SecurityChecker

def home(request):
    """Render the home page with the security check form"""
    return render(request, 'security_check.html')

def verify_security(request):
    """Process the form submission and check website security"""
    context = {}
    
    if request.method == 'POST':
        url = request.POST.get('url', '').strip()
        
        if not url:
            context['result'] = "Please enter a valid URL"
            context['is_secure'] = False
            return render(request, 'security_check.html', context)
        
        try:
            # Use our SecurityChecker class to analyze the URL
            checker = SecurityChecker(url)
            results = checker.check_security()
            
            # Pass results to the template
            context['url'] = url
            context['is_secure'] = results['is_secure']
            context['result'] = results['summary']
            context['details'] = results['details']
            
        except Exception as e:
            context['is_secure'] = False
            context['result'] = f"Error checking website security: {str(e)}"
    
    return render(request, 'security_check.html', context)