from django.shortcuts import redirect, render

from django.utils.text import slugify
from unidecode import unidecode
from .models import Category

# Create your views here.
def show_categories(request):
    categories = Category.objects.all()
    return render(request, 'categories.html', {'categories': categories})


def add_category(request):
    if request.method == "POST":
        category_name = request.POST.get("name")
        print(category_name)
        category_slug = slugify(unidecode(category_name))
        category_description = request.POST.get("description")
        category_is_active = request.POST.get("is_active") == "checked"
        category_image = request.FILES.get("image")

        category = Category(name = category_name, slug = category_slug, description = category_description, is_active = category_is_active, image = category_image)
        category.save()

        return redirect('/categories/')
    
    return render(request, 'add_category.html')