def test_placeholder():
    '''Test de base pour vérifier que pytest fonctionne'''
    assert True

def test_import():
    '''Test pour vérifier que les imports fonctionnent'''
    try:
        import pytest
        assert True
    except ImportError:
        assert False, 'pytest n''est pas installé'
