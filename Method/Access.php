<?php
namespace GDO\Security\Method;

use GDO\User\GDO_User;
use GDO\Table\MethodQueryTable;
use GDO\Security\GDO_AccountAccess;
use GDO\UI\GDT_DeleteButton;
use GDO\Core\GDO;
use GDO\DB\Query;
use GDO\Form\GDT_Form;
use GDO\Form\GDT_AntiCSRF;

final class Access extends MethodQueryTable
{
    public function gdoTable() : GDO { return GDO_AccountAccess::table(); }

    public function getQuery() : Query
    {
        $user = GDO_User::current();
        return parent::getQuery()->where("accacc_uid={$user->getID()}");
    }
    
    public function gdoHeaders() : array
    {
        $table = $this->gdoTable();
        return $table->getGDOColumns([
            'accacc_time', 'accacc_ip', 'accacc_isp', 'accacc_ua']);
    }
    
    public function getForm()
    {
        $form = GDT_Form::make()->slim();
        $form->addField(GDT_AntiCSRF::make());
        $form->actions()->addField(GDT_DeleteButton::make());
        return $form;
    }
    
    public function execute()
    {
        $form = $this->getForm();
        return parent::execute()->addField($form);
    }
}
